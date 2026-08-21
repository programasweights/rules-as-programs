"""Intent-first native editor for rule specifications and deployment."""

from __future__ import annotations

import threading
import json
import secrets
import time
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
    NSBox,
    NSBoxSeparator,
    NSButton,
    NSButtonTypeRadio,
    NSButtonTypeSwitch,
    NSColor,
    NSControlStateValueOff,
    NSControlStateValueOn,
    NSEventModifierFlagCommand,
    NSEventModifierFlagControl,
    NSEventModifierFlagOption,
    NSEventModifierFlagShift,
    NSFont,
    NSLayoutAttributeCenterY,
    NSLayoutAttributeLeading,
    NSLayoutConstraint,
    NSLineBreakByTruncatingTail,
    NSLayoutPriorityDefaultLow,
    NSMinYEdge,
    NSMenu,
    NSMenuItem,
    NSPasteboard,
    NSPasteboardTypeString,
    NSPopUpButton,
    NSPopover,
    NSPopoverBehaviorTransient,
    NSSearchField,
    NSScrollView,
    NSScreen,
    NSStackView,
    NSStackViewDistributionFill,
    NSToolbar,
    NSToolbarDisplayModeIconOnly,
    NSToolbarFlexibleSpaceItemIdentifier,
    NSToolbarItem,
    NSToolbarItemVisibilityPriorityHigh,
    NSToolbarItemVisibilityPriorityLow,
    NSToolbarItemVisibilityPriorityStandard,
    NSTextField,
    NSTextView,
    NSUserInterfaceLayoutOrientationHorizontal,
    NSUserInterfaceLayoutOrientationVertical,
    NSView,
    NSViewController,
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
from Foundation import (
    NSMakeRect,
    NSMakeSize,
    NSObject,
    NSUserNotification,
    NSUserNotificationCenter,
)
from PyObjCTools import AppHelper

from .. import ipc, rules_api, scaffold
from ..core.triggers import COMMON_TRIGGERS, ORDERED_TRIGGERS, TRIGGERS
from ..core import revisions, validation_store
from .layout import fit_rule_editor_layout
from .macos_controls import (
    ButtonRole,
    RAPCommandWindow,
    RAPFlippedView,
    set_button_symbol,
    style_button,
)
from .model import UIModel

def _on_main(callback: Callable[[], None]) -> None:
    AppHelper.callAfter(callback)


def _after_delay(
    seconds: float, callback: Callable[[], None]
) -> threading.Timer:
    dispatcher = _on_main
    timer = threading.Timer(seconds, lambda: dispatcher(callback))
    timer.daemon = True
    timer.start()
    return timer


def _activate(*constraints) -> None:
    NSLayoutConstraint.activateConstraints_([item for item in constraints if item])


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


class RAPRuleToolbarDelegate(NSObject):
    def toolbarAllowedItemIdentifiers_(self, _toolbar):
        owner = getattr(self, "owner", None)
        return (
            ([] if owner and owner.rule.get("new_draft") else ["rule.actions"])
            + ["rule.state",
            NSToolbarFlexibleSpaceItemIdentifier,
            "rule.advanced", "rule.deploy"]
        )

    def toolbarDefaultItemIdentifiers_(self, _toolbar):
        owner = getattr(self, "owner", None)
        return (
            ([] if owner and owner.rule.get("new_draft") else ["rule.actions"])
            + ["rule.state",
            NSToolbarFlexibleSpaceItemIdentifier,
            "rule.advanced", "rule.deploy"]
        )

    def toolbar_itemForItemIdentifier_willBeInsertedIntoToolbar_(
        self, _toolbar, identifier, _inserted
    ):
        owner = getattr(self, "owner", None)
        if owner is None:
            return None
        views = {
            "rule.actions": (owner.rule_actions_button, "Rule"),
            "rule.state": (owner.footer_status, "Status"),
            "rule.advanced": (owner.footer_advanced, "Advanced"),
            "rule.deploy": (owner.deploy_button, "Deploy"),
        }
        value = views.get(str(identifier))
        if value is None:
            return None
        view, label = value
        item = NSToolbarItem.alloc().initWithItemIdentifier_(identifier)
        item.setLabel_(label)
        item.setPaletteLabel_(label)
        item.setView_(view)
        key = str(identifier)
        if key == "rule.deploy":
            item.setVisibilityPriority_(
                NSToolbarItemVisibilityPriorityHigh)
            item.setMinSize_(NSMakeSize(118, 28))
            item.setMaxSize_(NSMakeSize(170, 32))
        elif key == "rule.advanced":
            item.setVisibilityPriority_(
                NSToolbarItemVisibilityPriorityStandard)
            item.setMinSize_(NSMakeSize(82, 24))
            item.setMaxSize_(NSMakeSize(108, 30))
        elif key == "rule.state":
            item.setVisibilityPriority_(
                NSToolbarItemVisibilityPriorityLow)
            item.setMinSize_(NSMakeSize(84, 20))
            item.setMaxSize_(NSMakeSize(180, 24))
        else:
            item.setVisibilityPriority_(
                NSToolbarItemVisibilityPriorityLow)
            item.setMinSize_(NSMakeSize(58, 24))
            item.setMaxSize_(NSMakeSize(82, 30))
        return item

class RAPRuleEditorWindow(RAPCommandWindow):
    def performKeyEquivalent_(self, event):
        owner = getattr(self, "owner", None)
        chars = str(event.charactersIgnoringModifiers() or "").lower()
        flags = int(event.modifierFlags())
        command = bool(flags & int(NSEventModifierFlagCommand))
        extra = bool(flags & int(
            NSEventModifierFlagControl
            | NSEventModifierFlagOption
            | NSEventModifierFlagShift))
        if owner and command and not extra and chars == "s":
            owner.save_draft()
            return True
        if owner and command and not extra and chars in ("\r", "\n"):
            owner.deploy()
            return True
        if owner and command and not extra and chars == "w":
            self.performClose_(None)
            return True
        return objc.super(RAPRuleEditorWindow, self).performKeyEquivalent_(event)


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
        self._callbacks: dict[int, Callable[[Any], None]] = {}
        self._target = RAPRuleEditorTarget.alloc().init()
        self._target._callbacks = self._callbacks
        self._text_delegate = RAPRuleEditorTextDelegate.alloc().init()
        self._text_delegate.owner = self
        self._next_tag = 1
        self._toolbar_delegate = RAPRuleToolbarDelegate.alloc().init()
        self._toolbar_delegate.owner = self
        self._key_views: list[Any] = []
        self._programmatic = False
        self._dirty = False
        self._source_dirty = False
        self._coverage_dirty = False
        self._busy = False
        self._shown = False
        self._scope_confirmed = False
        self._close_after_save = False
        self._advanced_window = None
        self._advanced_editor = None
        self._advanced_apply = None
        self._info_popover = None
        self._external_control_state: list[tuple[Any, str, bool]] = []
        self._lifecycle_confirmation_state: dict[str, int] | None = None
        self.full_source = ""
        self.name = ""
        self.original_name = ""
        self.description = ""
        self.spec = ""
        self.cases: list[tuple[str, str]] = []
        self.on: list[str] = []
        self.inputs: list[str] = []
        self.probes: dict[str, str] = {}
        self.channel = "finding"
        self.severity = "warn"
        self.allowed_label = "OK"
        self.simple_fuzzy = False
        self.managed_fuzzy = False
        self.custom = False
        self.inputs_inferred = False
        self.finding_context = None
        self.coverage_mode = "selected"
        self.selected_projects: list[str] = []
        self.projects: list[dict[str, str]] = []
        self.project_overrides: list[str] = []
        self.source_scope = ""
        self._active_coverage: dict[str, Any] = {
            "mode": "selected", "selected_projects": []}
        self._active_hash = ""
        self._working_hash = ""
        self._definition_hash = ""
        self._saved_source_hash = ""
        self.active_compiler = ""
        self.active_compiler_snapshot = ""
        self.active_program_id = ""
        self.active_compiler_mode = revisions.AUTOMATIC_COMPILER_MODE
        self.active_artifacts: dict[str, dict[str, Any]] = {}
        self.compiler_mode = revisions.AUTOMATIC_COMPILER_MODE
        self.draft_compiler = ""
        self.draft_compiler_snapshot = ""
        self._draft_compiler_explicit = False
        self._compiler_dirty = False
        self._current_source_hash = ""
        self._current_behavior_hash = ""
        self._active_behavior_hash = ""
        self.compiler_catalog: list[dict[str, Any]] = []
        self.compiler_catalog_cached = False
        self.compiler_catalog_offline = False
        self.compiler_catalog_fetched_at = 0.0
        self._compiler_catalog_attempted = False
        self._finetune_status: dict[str, Any] = {}
        self._finetune_poll_timer = None
        self._deployment_queue: dict[str, Any] = {}
        self._deployment_queue_poll_timer = None
        self._deployment_queue_poll_failures = 0
        self._deployment_queue_poll_recovery_thread = None
        self._notified_queue_terminal = ""
        self._pending_deployment_id = ""
        self._deployment_recovery_thread = None
        self._draft_generation = 0
        self._confirmed_spec_warning_hash = ""
        self._confirmed_build_discard_hash = ""
        self.validation_cases: list[dict[str, str]] = []
        self._saved_validation_cases = "[]"
        self._validation_dirty = False
        self._validation_save_generation = 0
        self._last_removed_validation = None
        self._validation_results: dict[str, dict[str, Any]] = {}
        self._validation_result_cache: dict[str, dict[str, Any]] = {}
        self.validation_result_labels: dict[str, NSTextField] = {}
        self._validation_run_key = ""
        self._validation_target: dict[str, Any] = {}
        self._validation_results_loaded = False
        self._validation_load_generation = 0
        self._busy_label = ""
        self._diagnostic_operation_id = ""
        self._content_fit_generation = 0
        self._content_fit_timer = None
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
        self.rule_id = str(rule.get("id", ""))
        self.finding_context = rule.get("_finding_context")
        self.full_source = str(rule.get("source", ""))
        self._apply_projection(
            rule.get("projection") or rules_api.source_projection(self.full_source))
        self.validation_cases = list(rule.get("validation_cases") or [])
        self._saved_validation_cases = json.dumps(
            self.validation_cases, sort_keys=True)
        self.original_name = self.name
        deployment = rule.get("deployment") or {}
        active_coverage = deployment.get("coverage") or {}
        self._active_coverage = {
            "mode": str(active_coverage.get("mode", "selected")),
            "selected_projects": sorted(
                active_coverage.get("selected_projects") or []),
        }
        draft_coverage = deployment.get("draft_coverage")
        coverage = draft_coverage or active_coverage
        self.coverage_mode = str(coverage.get("mode", "selected"))
        self.selected_projects = list(coverage.get("selected_projects") or [])
        self.projects = list(deployment.get("projects") or [])
        self.source_scope = str(
            deployment.get("source_scope") or rule.get("scope", ""))
        self.project_overrides = list(
            deployment.get("project_overrides") or [])
        if not self.selected_projects and project_root and rule.get("new_draft"):
            self.selected_projects = [project_root]
        self._active_hash = str(rule.get("active_hash", ""))
        self.active_compiler = str(
            (rule.get("active") or {}).get("compiler", ""))
        self.active_compiler_snapshot = str(
            (rule.get("active") or {}).get("compiler_snapshot", ""))
        self.active_program_id = str(
            (rule.get("active") or {}).get("program_id", ""))
        self.active_compiler_mode = str(
            (rule.get("active") or {}).get("compiler_mode")
            or revisions.AUTOMATIC_COMPILER_MODE)
        self.active_artifacts = dict(
            (rule.get("active") or {}).get("artifacts") or {})
        self.compiler_mode = self.active_compiler_mode
        self._active_behavior_hash = str(
            (rule.get("active") or {}).get("behavior_hash")
            or rule.get("active_behavior_hash", ""))
        self.draft_compiler = self.active_compiler
        self.draft_compiler_snapshot = self.active_compiler_snapshot
        if (draft_coverage or {}).get("compiler_mode") in revisions.COMPILER_MODES:
            self.compiler_mode = str(draft_coverage["compiler_mode"])
        if (draft_coverage or {}).get("compiler"):
            self.draft_compiler = str(draft_coverage["compiler"])
            self.draft_compiler_snapshot = str(
                (draft_coverage or {}).get("compiler_snapshot", ""))
            self._draft_compiler_explicit = (
                self.compiler_mode == revisions.EXPLICIT_COMPILER_MODE)
        self._compiler_dirty = self._compiler_selection_dirty()
        self._working_hash = str(rule.get("working_hash", ""))
        self._definition_hash = str(
            (rule.get("definition") or {}).get("source_hash", ""))
        self._saved_source_hash = revisions.hash_source(self.full_source)
        self._current_source_hash = self._saved_source_hash
        self._current_behavior_hash = revisions.behavior_hash(self.full_source)
        if not self._active_behavior_hash and self._active_hash:
            self._active_behavior_hash = str(
                rule.get("working_behavior_hash")
                if self._active_hash == self._working_hash else "")
        self._source_dirty = bool(rule.get("draft_changes"))
        self._coverage_dirty = {
            "mode": self.coverage_mode,
            "selected_projects": sorted(
                self.selected_projects
                if self.coverage_mode == "selected" else []),
        } != self._active_coverage
        if rule.get("new_draft") and not draft_coverage:
            self._coverage_dirty = False
        self._dirty = (
            self._source_dirty
            or self._coverage_dirty
            or self._compiler_dirty
            or self._validation_dirty)
        self._scope_confirmed = bool(
            (draft_coverage or {}).get("confirmed"))
        self._build_window()
        self._build_content()
        self._refresh_ui(sync_text=True)

    @objc.python_method
    def _apply_projection(self, projection: dict[str, Any]) -> None:
        self.simple_fuzzy = bool(projection.get("simple_fuzzy"))
        self.managed_fuzzy = bool(projection.get("managed_fuzzy"))
        self.custom = not projection.get("ok") or bool(projection.get("custom"))
        self.name = str(
            projection.get("name")
            or self.rule.get("name")
            or self.rule.get("title")
            or "Untitled rule"
        )
        self.spec = str(projection.get("spec", ""))
        self.description = self.spec
        if self.rule.get("new_draft"):
            if self.name.strip().lower() == "untitled rule":
                self.name = ""
        self.allowed_label = str(projection.get("allowed_label", "OK"))
        self.cases = []
        self.on = list(projection.get("on", []))
        self.inputs = list(projection.get("inputs", []))
        self.probes = dict(projection.get("probes", {}))
        self.channel = str(projection.get("channel", "finding"))
        self.severity = str(projection.get("severity", "warn"))
        self.inputs_inferred = bool(projection.get("inputs_inferred"))
        self.trigger = str(projection.get("trigger", "afterAgentResponse"))
        if (
            self.rule.get("new_draft")
            and not self.rule.get("path")
            and not self.rule.get("definition")
        ):
            self.trigger = ""
        self.input_pointer = str(projection.get("input_pointer", ""))

    @objc.python_method
    def _build_window(self) -> None:
        screen = NSScreen.mainScreen()
        visible = screen.visibleFrame().size if screen else NSMakeSize(1200, 800)
        layout = fit_rule_editor_layout(
            advanced=self.custom,
            optional_height=62 if self.finding_context else 0,
            available_width=float(visible.width),
            available_height=float(visible.height),
        )
        mask = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskResizable
            | NSWindowStyleMaskMiniaturizable
        )
        self.window = RAPRuleEditorWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, layout.width, layout.height),
            mask,
            NSBackingStoreBuffered,
            False,
        )
        self.window.owner = self
        self.window.setReleasedWhenClosed_(False)
        self.window.setDelegate_(self)
        self.window.setContentMinSize_(NSMakeSize(680, 360))
        self.window.setTitle_("Rule Editor")

    @objc.python_method
    def _wire(
        self, control, callback: Callable[[Any], None], *,
        key_view: bool = True,
    ):
        tag = self._next_tag
        self._next_tag += 1
        self._callbacks[tag] = callback
        control.setTag_(tag)
        control.setTarget_(self._target)
        control.setAction_("invoke:")
        if key_view and hasattr(control, "setNextKeyView_"):
            self._key_views.append(control)
        return control

    @objc.python_method
    def _button(
        self,
        title: str,
        callback: Callable[[Any], None],
        *,
        role: ButtonRole = "secondary",
        accessibility: str | None = None,
        key_view: bool = True,
    ) -> NSButton:
        button = NSButton.alloc().init()
        button.setTitle_(title)
        style_button(
            button,
            role=role,
            accessibility=accessibility or title.rstrip("…"),
        )
        return self._wire(button, callback, key_view=key_view)

    @staticmethod
    def _label(
        text: str,
        *,
        size: float = 11,
        bold: bool = False,
        color=None,
        lines: int = 1,
    ) -> NSTextField:
        label = NSTextField.labelWithString_(str(text))
        label.setFont_(
            NSFont.boldSystemFontOfSize_(size)
            if bold else NSFont.systemFontOfSize_(size))
        label.setTextColor_(color or NSColor.labelColor())
        label.setMaximumNumberOfLines_(lines)
        if lines != 1:
            label.cell().setWraps_(True)
            label.cell().setScrollable_(False)
            label.setPreferredMaxLayoutWidth_(680)
            label.setContentCompressionResistancePriority_forOrientation_(
                1, NSUserInterfaceLayoutOrientationHorizontal)
            label.setContentHuggingPriority_forOrientation_(
                1, NSUserInterfaceLayoutOrientationHorizontal)
        return label

    @staticmethod
    def _stack(views, *, vertical: bool, spacing: float = 8) -> NSStackView:
        stack = NSStackView.stackViewWithViews_(list(views))
        stack.setOrientation_(
            NSUserInterfaceLayoutOrientationVertical
            if vertical else NSUserInterfaceLayoutOrientationHorizontal)
        stack.setSpacing_(spacing)
        stack.setDistribution_(NSStackViewDistributionFill)
        stack.setAlignment_(
            NSLayoutAttributeLeading
            if vertical else NSLayoutAttributeCenterY)
        stack.setTranslatesAutoresizingMaskIntoConstraints_(False)
        return stack

    @staticmethod
    def _spacer() -> NSView:
        spacer = NSView.alloc().init()
        spacer.setContentHuggingPriority_forOrientation_(
            NSLayoutPriorityDefaultLow, NSUserInterfaceLayoutOrientationHorizontal)
        return spacer

    @objc.python_method
    def _text_scroll(
        self, text: str, *, prose: bool, minimum_height: float
    ) -> tuple[NSScrollView, NSTextView]:
        scroll = NSScrollView.alloc().init()
        scroll.setHasVerticalScroller_(True)
        scroll.setHasHorizontalScroller_(not prose)
        scroll.setBorderType_(1)
        scroll.setTranslatesAutoresizingMaskIntoConstraints_(False)
        editor = NSTextView.alloc().initWithFrame_(
            NSMakeRect(0, 0, 700, minimum_height))
        editor.setRichText_(False)
        editor.setAllowsUndo_(True)
        editor.setEditable_(not self._busy)
        editor.setAutomaticQuoteSubstitutionEnabled_(False)
        editor.setAutomaticDashSubstitutionEnabled_(False)
        editor.setAutomaticTextReplacementEnabled_(False)
        editor.setFont_(
            NSFont.systemFontOfSize_(13)
            if prose else NSFont.userFixedPitchFontOfSize_(11.5))
        editor.setHorizontallyResizable_(not prose)
        editor.setVerticallyResizable_(True)
        editor.setAutoresizingMask_(NSViewWidthSizable)
        editor.textContainer().setWidthTracksTextView_(prose)
        editor.setDelegate_(self._text_delegate)
        editor.setString_(text)
        scroll.setDocumentView_(editor)
        _activate(
            scroll.heightAnchor().constraintGreaterThanOrEqualToConstant_(
                minimum_height))
        return scroll, editor

    @objc.python_method
    def _heading(self, title: str, help_text: str | None = None) -> NSStackView:
        label = self._label(title, size=12, bold=True)
        views = [label]
        if help_text:
            info = self._button(
                "",
                lambda sender, t=title, b=help_text: self.show_info(
                    sender, t, b),
                role="flat",
                accessibility=f"About {title}",
            )
            set_button_symbol(
                info, "info.circle", f"About {title}", fallback="Info")
            views.append(info)
        views.append(self._spacer())
        return self._stack(views, vertical=False, spacing=6)

    @objc.python_method
    def _build_content(self) -> None:
        root = self.window.contentView()
        footer = NSView.alloc().init()
        footer.setTranslatesAutoresizingMaskIntoConstraints_(False)
        separator = NSBox.alloc().init()
        separator.setBoxType_(NSBoxSeparator)
        separator.setTranslatesAutoresizingMaskIntoConstraints_(False)
        scroll = NSScrollView.alloc().init()
        scroll.setHasVerticalScroller_(True)
        scroll.setDrawsBackground_(False)
        scroll.setTranslatesAutoresizingMaskIntoConstraints_(False)
        self.content_scroll = scroll
        root.addSubview_(scroll)
        root.addSubview_(separator)
        root.addSubview_(footer)
        self._footer_height_constraint = (
            footer.heightAnchor().constraintEqualToConstant_(1))
        _activate(
            scroll.topAnchor().constraintEqualToAnchor_(root.topAnchor()),
            scroll.leadingAnchor().constraintEqualToAnchor_(root.leadingAnchor()),
            scroll.trailingAnchor().constraintEqualToAnchor_(root.trailingAnchor()),
            scroll.bottomAnchor().constraintEqualToAnchor_(separator.topAnchor()),
            separator.leadingAnchor().constraintEqualToAnchor_(root.leadingAnchor()),
            separator.trailingAnchor().constraintEqualToAnchor_(root.trailingAnchor()),
            separator.bottomAnchor().constraintEqualToAnchor_(footer.topAnchor()),
            separator.heightAnchor().constraintEqualToConstant_(1),
            footer.leadingAnchor().constraintEqualToAnchor_(root.leadingAnchor()),
            footer.trailingAnchor().constraintEqualToAnchor_(root.trailingAnchor()),
            footer.bottomAnchor().constraintEqualToAnchor_(root.bottomAnchor()),
            self._footer_height_constraint,
        )

        document = RAPFlippedView.alloc().init()
        document.setTranslatesAutoresizingMaskIntoConstraints_(False)
        scroll.setDocumentView_(document)
        content = self._stack([], vertical=True, spacing=10)
        document.addSubview_(content)
        _activate(
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
                document.bottomAnchor(), -20),
        )

        self.name_field = NSTextField.alloc().init()
        self.name_field.setFont_(NSFont.systemFontOfSize_(15))
        self.name_field.setPlaceholderString_("Rule name")
        self.name_field.setDelegate_(self._text_delegate)
        self.name_field.setAccessibilityLabel_("Rule name")
        name_row = self._stack(
            [self._label("Rule name", size=12, bold=True), self.name_field],
            vertical=False, spacing=12)
        _activate(self.name_field.widthAnchor().constraintGreaterThanOrEqualToConstant_(360))
        content.addArrangedSubview_(name_row)
        self.state_label = self._label(
            "Draft", size=10, bold=True, color=NSColor.controlAccentColor())
        content.addArrangedSubview_(self.state_label)
        self.state_label.setHidden_(True)

        self.finding_label = self._label(
            "", size=10, color=NSColor.secondaryLabelColor(), lines=3)
        self.finding_copy_button = self._button(
            "Copy Input", lambda _sender: self.copy_finding_input(),
            role="flat")
        self.finding_show_button = self._button(
            "Show Finding", lambda _sender: self.show_finding(),
            role="flat")
        self.finding_callout = self._stack([
            self._label("Tuning from finding", size=11, bold=True),
            self.finding_label,
            self._stack([
                self.finding_show_button,
                self.finding_copy_button,
                self._spacer(),
            ], vertical=False, spacing=8),
        ], vertical=True, spacing=4)
        content.addArrangedSubview_(self.finding_callout)
        self._refresh_finding_context()

        spec_heading = self._heading(
            "PAW specification",
            "This exact text is passed to paw.compile(). RAP does not append or "
            "rewrite it.",
        )
        self.advanced_button = self._button(
            "View Python…", lambda _sender: self.show_advanced(),
            role="flat", accessibility="View underlying Python")
        self.advanced_button.setHidden_(True)
        content.addArrangedSubview_(spec_heading)
        self.spec_scroll, self.description_editor = self._text_scroll(
            self.description, prose=True, minimum_height=100)
        description_lines = max(
            4, self.description.count("\n") + len(self.description) // 90 + 1)
        self.spec_height_constraint = (
            self.spec_scroll.heightAnchor().constraintEqualToConstant_(
                min(260, max(100, description_lines * 18 + 24))))
        _activate(self.spec_height_constraint)
        self.spec_scroll.setContentHuggingPriority_forOrientation_(
            NSLayoutPriorityDefaultLow,
            NSUserInterfaceLayoutOrientationVertical)
        self.spec_scroll.setContentCompressionResistancePriority_forOrientation_(
            NSLayoutPriorityDefaultLow,
            NSUserInterfaceLayoutOrientationVertical)
        self.description_editor.setAccessibilityLabel_("Rule specification")
        self.description_editor.setPlaceholderString_(
            "Describe when the input should be shown and what PAW should return.")
        content.addArrangedSubview_(self.spec_scroll)
        self.custom_label = self._label(
            "This is a custom Python rule. Edit its behavior through View Python.",
            size=11, color=NSColor.systemOrangeColor(), lines=2)
        content.addArrangedSubview_(self.custom_label)

        self.scope_heading = self._heading(
            "Runs in",
            "All projects includes current and future projects. Selected projects "
            "runs only in the projects you choose.",
        )
        content.addArrangedSubview_(self.scope_heading)
        self.all_projects_radio = NSButton.alloc().init()
        self.all_projects_radio.setButtonType_(NSButtonTypeRadio)
        self.all_projects_radio.setTitle_("All projects")
        self._wire(
            self.all_projects_radio,
            lambda _sender: self.set_coverage_mode("all"))
        self.selected_projects_radio = NSButton.alloc().init()
        self.selected_projects_radio.setButtonType_(NSButtonTypeRadio)
        self.selected_projects_radio.setTitle_("Selected projects")
        self._wire(
            self.selected_projects_radio,
            lambda _sender: self.set_coverage_mode("selected"))
        self.edit_projects_button = self._button(
            "Choose projects…", lambda _sender: self.show_projects_sheet(),
            role="flat")
        scope_row = self._stack(
            [
                self.all_projects_radio,
                self.selected_projects_radio,
                self.edit_projects_button,
                self._spacer(),
            ],
            vertical=False,
            spacing=12,
        )
        content.addArrangedSubview_(scope_row)
        self.scope_summary = self._label(
            "", size=10, color=NSColor.secondaryLabelColor(), lines=2)
        content.addArrangedSubview_(self.scope_summary)
        self.scope_heading.setHidden_(True)
        scope_row.setHidden_(True)
        self.scope_summary.setHidden_(True)

        self.trigger_buttons: dict[str, NSButton] = {}
        self.input_buttons: dict[str, NSButton] = {}
        self.trigger_popup = NSPopUpButton.alloc().init()
        self.trigger_popup.addItemWithTitle_(
            "Choose a trigger — Required")
        self.trigger_popup.lastItem().setRepresentedObject_("")
        for definition in COMMON_TRIGGERS:
            self.trigger_popup.addItemWithTitle_(definition.label)
            self.trigger_popup.lastItem().setRepresentedObject_(definition.hook)
        self.trigger_popup.menu().addItem_(NSMenuItem.separatorItem())
        self.trigger_popup.addItemWithTitle_("More actions…")
        self.trigger_popup.lastItem().setRepresentedObject_("__more__")
        self._wire(self.trigger_popup, self.trigger_changed)
        self.trigger_error_label = self._label(
            "Choose when this rule should run.",
            size=10,
            color=NSColor.systemRedColor(),
        )
        self.trigger_error_label.setHidden_(True)
        self.input_contract_label = self._label(
            "", size=10, color=NSColor.secondaryLabelColor(), lines=2)
        self.input_mapping_button = self._button(
            "Advanced input…", lambda _sender: self.show_input_mapping(),
            role="flat")
        self.input_mapping_button.setHidden_(True)
        self.input_row = self._stack([
            self._label("Input:", size=12, bold=True),
            self.input_contract_label,
            self._spacer(),
        ], vertical=False, spacing=6)
        self.metadata_stack = self._stack([
            self._label("Trigger", size=12, bold=True),
            self.trigger_popup,
            self.trigger_error_label,
            self.input_row,
        ], vertical=True, spacing=7)
        self.metadata_stack.setContentHuggingPriority_forOrientation_(
            1000, NSUserInterfaceLayoutOrientationVertical)
        content.addArrangedSubview_(self.metadata_stack)
        self.inferred_label = self._label(
            "",
            size=10, color=NSColor.secondaryLabelColor())
        self.inferred_label.setHidden_(True)
        content.addArrangedSubview_(self.inferred_label)

        content.removeArrangedSubview_(self.metadata_stack)
        self.metadata_stack.removeFromSuperview()
        content.insertArrangedSubview_atIndex_(self.metadata_stack, 3)

        self.spec_guidance_label = self._label(
            "", size=10, color=NSColor.secondaryLabelColor(), lines=2)
        self.spec_guidance_label.setContentHuggingPriority_forOrientation_(
            1000, NSUserInterfaceLayoutOrientationVertical)
        content.insertArrangedSubview_atIndex_(self.spec_guidance_label, 6)

        self.validation_controls: list[
            tuple[NSTextField, NSPopUpButton]
        ] = []
        self.validation_stack = self._stack(
            [], vertical=True, spacing=6)
        validation_document = RAPFlippedView.alloc().init()
        validation_document.setTranslatesAutoresizingMaskIntoConstraints_(
            False)
        validation_scroll = NSScrollView.alloc().init()
        validation_scroll.setHasVerticalScroller_(True)
        validation_scroll.setAutohidesScrollers_(False)
        validation_scroll.setDrawsBackground_(True)
        validation_scroll.setBackgroundColor_(NSColor.controlBackgroundColor())
        validation_scroll.setBorderType_(1)
        validation_scroll.setDocumentView_(validation_document)
        validation_scroll.setTranslatesAutoresizingMaskIntoConstraints_(False)
        validation_document.addSubview_(self.validation_stack)
        _activate(
            validation_document.topAnchor().constraintEqualToAnchor_(
                validation_scroll.contentView().topAnchor()),
            validation_document.leadingAnchor().constraintEqualToAnchor_(
                validation_scroll.contentView().leadingAnchor()),
            validation_document.widthAnchor().constraintEqualToAnchor_(
                validation_scroll.contentView().widthAnchor()),
            self.validation_stack.topAnchor().constraintEqualToAnchor_constant_(
                validation_document.topAnchor(), 4),
            self.validation_stack.leadingAnchor().constraintEqualToAnchor_constant_(
                validation_document.leadingAnchor(), 2),
            self.validation_stack.trailingAnchor().constraintEqualToAnchor_constant_(
                validation_document.trailingAnchor(), -8),
            self.validation_stack.bottomAnchor().constraintEqualToAnchor_constant_(
                validation_document.bottomAnchor(), -4),
        )
        self.validation_scroll = validation_scroll
        self.validation_document = validation_document
        self.validation_height_constraint = (
            validation_scroll.heightAnchor().constraintEqualToConstant_(44))
        self.validation_document_height = (
            validation_document.heightAnchor().constraintEqualToConstant_(44))
        _activate(
            self.validation_height_constraint,
            self.validation_document_height,
        )
        self.add_validation_button = self._button(
            "+ Add case", lambda _sender: self.add_validation_case(),
            role="flat")
        self.run_validation_button = self._button(
            "Run Tests", lambda _sender: self.run_validation_cases(),
            role="flat")
        self.validation_count_label = self._label(
            "", size=9.5, color=NSColor.secondaryLabelColor())
        self.validation_undo_button = self._button(
            "Undo", lambda _sender: self.undo_remove_validation_case(),
            role="flat")
        self.validation_undo_button.setHidden_(True)
        self.validation_actions_button = self._button(
            "Actions…", lambda sender: self.show_validation_actions(sender),
            role="flat")
        self.validation_status = self._label(
            "", size=9.5, color=NSColor.secondaryLabelColor(), lines=1)
        self.validation_status.setContentCompressionResistancePriority_forOrientation_(
            1, NSUserInterfaceLayoutOrientationHorizontal)
        validation_title_row = self._stack([
            self._label("Validation cases · Optional", size=12, bold=True),
            self.validation_count_label,
            self.validation_status,
            self._spacer(),
            self.validation_undo_button,
            self.run_validation_button,
            self.add_validation_button,
            self.validation_actions_button,
        ], vertical=False, spacing=8)
        input_header = self._label(
            "Input", size=9.5, bold=True,
            color=NSColor.secondaryLabelColor())
        expected_header = self._label(
            "Expected", size=9.5, bold=True,
            color=NSColor.secondaryLabelColor())
        result_header = self._label(
            "Last result", size=9.5, bold=True,
            color=NSColor.secondaryLabelColor())
        column_header = self._stack([
            input_header,
            expected_header,
            result_header,
            NSView.alloc().init(),
            NSView.alloc().init(),
        ], vertical=False, spacing=8)
        _activate(
            input_header.widthAnchor().constraintGreaterThanOrEqualToConstant_(
                300),
            expected_header.widthAnchor().constraintEqualToConstant_(95),
            result_header.widthAnchor().constraintEqualToConstant_(170),
            column_header.arrangedSubviews()[-2].widthAnchor().constraintEqualToConstant_(28),
            column_header.arrangedSubviews()[-1].widthAnchor().constraintEqualToConstant_(28),
        )
        self.validation_section = self._stack([
            validation_title_row,
            column_header,
            validation_scroll,
        ], vertical=True, spacing=7)
        self.validation_column_header = column_header
        self.validation_section.setContentHuggingPriority_forOrientation_(
            1000, NSUserInterfaceLayoutOrientationVertical)
        content.insertArrangedSubview_atIndex_(self.validation_section, 7)
        self._render_validation_cases()

        self.observed_runs_button = self._button(
            "View History…", lambda _sender: self.show_evaluation_history(),
            role="flat")
        self.observed_runs_row = self._stack([
            self._label("Observed runs", size=12, bold=True),
            self._label(
                "Inspect every real input and prediction.",
                size=9.5, color=NSColor.secondaryLabelColor()),
            self._spacer(),
            self.observed_runs_button,
        ], vertical=False, spacing=8)
        content.insertArrangedSubview_atIndex_(self.observed_runs_row, 8)

        self.compiler_status_label = self._label(
            "", size=10, color=NSColor.secondaryLabelColor(), lines=2)
        self.compiler_action_button = self._button(
            "Compilation…", lambda _sender: self.compiler_action(),
            role="flat")
        self.compiler_row = self._stack([
            self._label("Draft compiler", size=12, bold=True),
            self.compiler_status_label,
            self._spacer(),
            self.compiler_action_button,
        ], vertical=False, spacing=8)
        content.insertArrangedSubview_atIndex_(self.compiler_row, 9)

        self.applies_summary = self._label(
            "", size=10, color=NSColor.secondaryLabelColor(), lines=2)
        self.scope_change_button = self._button(
            "Change…", lambda _sender: self.show_projects_sheet(), role="flat")
        self.applies_row = self._stack([
            self._label("Applies to", size=12, bold=True),
            self.applies_summary,
            self.scope_change_button,
        ], vertical=False, spacing=8)
        self.applies_row.setContentHuggingPriority_forOrientation_(
            1000, NSUserInterfaceLayoutOrientationVertical)
        content.insertArrangedSubview_atIndex_(self.applies_row, 10)

        self.diagnostics_label = self._label(
            "", size=10, color=NSColor.secondaryLabelColor(), lines=5)
        self.diagnostics_label.setHidden_(True)
        content.addArrangedSubview_(self.diagnostics_label)
        self._content_stack = content

        self.lifecycle_button = self._button(
            self._lifecycle_title(),
            lambda _sender: self.confirm_lifecycle_action(),
            role="destructive",
        )
        self.lifecycle_button.setHidden_(True)
        self.rule_actions_button = self._button(
            "Rule…", lambda sender: self.show_rule_actions(sender), role="flat")
        self.footer_status = self._label(
            "", size=10, color=NSColor.secondaryLabelColor())
        self.footer_status.cell().setLineBreakMode_(
            NSLineBreakByTruncatingTail)
        self.footer_status.setFrameSize_(NSMakeSize(180, 20))
        self.footer_advanced = self._button(
            "Advanced…", lambda sender: self.show_advanced_menu(sender),
            role="flat")
        self.deploy_button = self._button(
            "Deploy", lambda _sender: self.deploy(), role="primary")
        toolbar = NSToolbar.alloc().initWithIdentifier_("RuleEditorToolbar")
        toolbar.setDelegate_(self._toolbar_delegate)
        toolbar.setAllowsUserCustomization_(False)
        toolbar.setDisplayMode_(NSToolbarDisplayModeIconOnly)
        self.window.setToolbar_(toolbar)
        self.toolbar = toolbar
        self._interactive_controls = [
            self.name_field,
            self.description_editor,
            self.all_projects_radio,
            self.selected_projects_radio,
            self.edit_projects_button,
            self.trigger_popup,
            self.input_mapping_button,
            self.scope_change_button,
            self.run_validation_button,
            self.add_validation_button,
            self.observed_runs_button,
            self.compiler_action_button,
            self.advanced_button,
            self.finding_show_button,
            self.finding_copy_button,
            self.footer_advanced,
            self.deploy_button,
            self.rule_actions_button,
            *self.trigger_buttons.values(),
            *self.input_buttons.values(),
        ]
        self._recalculate_key_loop()
        root.layoutSubtreeIfNeeded()
        self._fit_spec_width()

    @objc.python_method
    def _recalculate_key_loop(self) -> None:
        def visible(control) -> bool:
            view = control
            while view is not None:
                if hasattr(view, "isHidden") and view.isHidden():
                    return False
                view = view.superview() if hasattr(view, "superview") else None
            return True

        ordered = [
            self.name_field,
            self.finding_show_button,
            self.finding_copy_button,
            self.trigger_popup,
            self.description_editor,
            *[
                control
                for pair in getattr(self, "validation_controls", [])
                for control in pair
            ],
            self.run_validation_button,
            self.add_validation_button,
            self.observed_runs_button,
            self.compiler_action_button,
            self.scope_change_button,
            self.rule_actions_button,
            self.footer_advanced,
            self.deploy_button,
        ]
        ordered.extend(
            control for control in self._key_views
            if all(control != existing for existing in ordered)
        )
        ordered = [
            control for control in ordered
            if control is not None
            and visible(control)
            and (not hasattr(control, "isEnabled") or control.isEnabled())
        ]
        for current, following in zip(
            ordered, ordered[1:] + ordered[:1]
        ):
            current.setNextKeyView_(following)
        self.window.setInitialFirstResponder_(self.name_field)

    @objc.python_method
    def _fit_spec_width(self) -> None:
        if not getattr(self, "spec_scroll", None):
            return
        size = self.spec_scroll.contentSize()
        if size.width <= 0:
            return
        height = max(float(size.height), float(
            self.description_editor.frame().size.height))
        self.description_editor.setFrameSize_(NSMakeSize(size.width, height))
        self.description_editor.textContainer().setContainerSize_(
            NSMakeSize(size.width, 10_000_000))

    @objc.python_method
    def _fit_window_to_content(self) -> None:
        self.window.contentView().layoutSubtreeIfNeeded()
        fitting_height = float(self._content_stack.fittingSize().height) + 40
        screen = self.window.screen() or NSScreen.mainScreen()
        maximum = (
            float(screen.visibleFrame().size.height) - 80
            if screen else 720)
        desired = max(360, min(maximum, fitting_height))
        self.window.setContentSize_(NSMakeSize(
            max(680, self.window.contentView().frame().size.width),
            desired))

    @objc.python_method
    def _lifecycle_title(self) -> str:
        if self.rule.get("new_draft") and not self.rule.get("path"):
            return "Discard Draft"
        if self.rule.get("new_draft"):
            return "Delete Draft…"
        if self.rule.get("scope") == "project" and self.rule.get("customized_from"):
            return "Use Shared Version…"
        if self.rule.get("is_builtin"):
            return "Remove Installed Rule…"
        return "Delete Rule…"

    @objc.python_method
    def _capture(self) -> None:
        if self._programmatic:
            return
        self.name = str(self.name_field.stringValue()).strip()
        if not self.custom:
            self.spec = str(self.description_editor.string()).strip()
            self.description = self.spec
            self.cases = []

    @objc.python_method
    def _compose(self) -> tuple[bool, str, str]:
        self._capture()
        self._capture_validation_cases()
        if self.custom:
            ok, source, error = rules_api.patch_rule_identity(
                self.full_source, self.rule_id, self.name)
            return ok, source, error
        if self.managed_fuzzy:
            projection = rules_api.source_projection(self.full_source)
            ok, source, error = rules_api.patch_source_projection(
                self.full_source,
                trigger=self.trigger,
                input_pointer=self.input_pointer,
                function_source=projection.get("function_source", ""),
                spec=self.spec,
            )
            if ok:
                ok, source, error = rules_api.patch_rule_identity(
                    source, self.rule_id, self.name)
            return ok, source, error
        ok, source, error = rules_api.patch_source_projection(
            self.full_source,
            trigger=self.trigger,
            input_pointer=self.input_pointer,
            function_source=rules_api.source_projection(
                self.full_source).get("function_source", ""),
            spec=self.spec or None,
        )
        if ok:
            ok, source, error = rules_api.patch_rule_identity(
                source, self.rule_id, self.name)
        return ok, source, error

    @objc.python_method
    def _refresh_ui(self, *, sync_text: bool = False) -> None:
        self._programmatic = True
        if sync_text:
            self.name_field.setStringValue_(self.name)
            self.description_editor.setString_(self.description)
            self._render_validation_cases()
            self._fit_description_height()
        for kind, button in self.trigger_buttons.items():
            button.setState_(
                NSControlStateValueOn if kind in self.on
                else NSControlStateValueOff)
        for kind, button in self.input_buttons.items():
            button.setState_(
                NSControlStateValueOn if kind in self.inputs
                else NSControlStateValueOff)
        trigger_item = next(
            (
                item for item in self.trigger_popup.itemArray()
                if str(item.representedObject() or "") == self.trigger
            ),
            None,
        )
        definition = TRIGGERS.get(self.trigger)
        if trigger_item is None and definition is not None:
            self.trigger_popup.insertItemWithTitle_atIndex_(
                definition.label, 0)
            trigger_item = self.trigger_popup.itemAtIndex_(0)
            trigger_item.setRepresentedObject_(definition.hook)
        if trigger_item is not None:
            self.trigger_popup.selectItem_(trigger_item)
        pointer = self.input_pointer or (
            definition.input_pointer if definition else "")
        source = "rule override" if self.input_pointer else "default"
        self.input_contract_label.setStringValue_(
            (
                f"{definition.input_label}"
            )
            if definition else "Choose one supported trigger.")
        self._refresh_spec_guidance()
        self.spec_guidance_label.setHidden_(self.custom)
        self.validation_section.setHidden_(self.custom)
        self.observed_runs_row.setHidden_(self.custom)
        self.observed_runs_button.setEnabled_(
            bool(self._active_hash) and not self._busy)
        self.applies_row.setHidden_(self.custom)
        self.all_projects_radio.setState_(
            NSControlStateValueOn
            if self.coverage_mode == "all" else NSControlStateValueOff)
        self.selected_projects_radio.setState_(
            NSControlStateValueOn
            if self.coverage_mode == "selected" else NSControlStateValueOff)
        self.edit_projects_button.setEnabled_(
            self.coverage_mode == "selected" and not self._busy)
        selected_names = [
            item["name"] for item in self.projects
            if item.get("path") in self.selected_projects
        ]
        self.scope_summary.setStringValue_(
            "Runs in every current and future project."
            if self.coverage_mode == "all"
            else (
                ", ".join(selected_names)
                if selected_names else "No projects selected."
            )
        )
        self.applies_summary.setStringValue_(
            "All projects"
            if self.coverage_mode == "all"
            else (
                f"This project · {selected_names[0]}"
                if (
                    len(selected_names) == 1
                    and self.selected_projects == [self.project_root]
                )
                else f"{len(selected_names)} selected project"
                f"{'s' if len(selected_names) != 1 else ''}"
                if selected_names else "No projects selected"
            ))
        self.custom_label.setHidden_(not self.custom)
        self.metadata_stack.setHidden_(self.custom)
        self.inferred_label.setHidden_(
            self.custom or not self.inputs_inferred)
        self.description_editor.setEditable_(not self.custom and not self._busy)
        self.lifecycle_button.setTitle_(self._lifecycle_title())
        if self._busy:
            state = self._busy_label or "Working"
        elif self.rule.get("_deploy_failed"):
            state = "Deploy failed"
        elif self.rule.get("new_draft") and not self.rule.get("path"):
            state = "Draft"
        elif self._dirty or (
            self._working_hash and self._active_hash
            and self._working_hash != self._active_hash
        ):
            state = "Changes not deployed"
        elif self._active_hash:
            state = "Deployed"
        else:
            state = "Not deployed"
        self.state_label.setStringValue_(state)
        deploy_needed = bool(
            self.rule.get("new_draft")
            or self._dirty
            or self._compiler_dirty
            or not self._active_hash
            or (
                self._working_hash
                and self._working_hash != self._active_hash
            )
        )
        basic_ready = (
            self.custom
            or (
                bool(self.name.strip())
                and bool(self.spec.strip())
                and self.trigger in TRIGGERS
                and (
                    not self.rule.get("new_draft")
                    or self.name.strip().lower() != "untitled rule"
                )
            )
        )
        raw_job = self._finetune_status.get("job") or {}
        raw_job_status = str(raw_job.get("status", ""))
        automatic_optimizing = bool(
            raw_job.get("automatic")
            and raw_job_status in (
                "waiting_for_build", "building", "checking", "deploying",
            )
            and self._job_matches_current_behavior(raw_job)
        )
        stale_build_running = bool(
            raw_job_status == "building"
            and not self._job_matches_current_behavior(raw_job)
        )
        job = self._draft_candidate_job()
        job_status = str(job.get("status", ""))
        active_compiler_label = self.compiler_label(
            self.resolved_active_compiler())
        draft_compiler = self.resolved_draft_compiler()
        draft_compiler_label = self.compiler_label(draft_compiler)
        draft_requires_build = self.compiler_requires_build(draft_compiler)
        draft_program_id = self._draft_program_id()
        draft_ready = bool(
            not draft_requires_build or draft_program_id)
        queue_status = str(self._deployment_queue.get("status", ""))
        queue_pending = queue_status in (
            "waiting_for_build", "building", "checking", "validating", "deploying",
            "cancelling")
        can_queue = bool(
            draft_requires_build
            and not draft_program_id
            and job_status == "building"
        )
        if not self._active_hash:
            deployed_copy = "Not deployed"
        elif self.compiler_mode == revisions.AUTOMATIC_COMPILER_MODE:
            deployed_copy = f"Automatic · Active: {active_compiler_label}"
            if automatic_optimizing:
                deployed_copy += " · optimizing…"
        else:
            deployed_copy = f"Deployed: {active_compiler_label}"
        if self.compiler_mode == revisions.AUTOMATIC_COMPILER_MODE:
            draft_copy = (
                f"Deploys with {draft_compiler_label} · optimizes in background"
            )
            compiler_action = "Choose…"
        elif job_status == "building":
            draft_copy = f"Draft: {draft_compiler_label} · building…"
            compiler_action = "Building…"
        elif draft_requires_build and not draft_ready:
            draft_copy = f"Draft: {draft_compiler_label} · build required"
            compiler_action = "Choose…"
        else:
            draft_copy = f"Draft: {draft_compiler_label} · ready"
            compiler_action = "Choose…"
        if queue_pending:
            phase = str(
                self._deployment_queue.get("phase")
                or "Deployment queued")
            elapsed = max(
                0, int(time.time() - float(
                    self._deployment_queue.get("created_at", time.time()))))
            draft_copy = (
                f"Draft: {draft_compiler_label} · {phase.lower()} "
                f"· {elapsed // 60}:{elapsed % 60:02d} elapsed"
            )
            compiler_action = "Cancel Queue…"
        compiler_copy = f"{draft_copy}   {deployed_copy}"
        self.compiler_status_label.setStringValue_(compiler_copy)
        self.compiler_action_button.setTitle_(compiler_action)
        self.compiler_action_button.setEnabled_(not self._busy)
        self.compiler_row.setHidden_(self.custom or not self.simple_fuzzy)
        status_copy = state
        self.footer_status.setStringValue_(status_copy)
        self.deploy_button.setEnabled_(
            deploy_needed
            and (draft_ready or can_queue)
            and not queue_pending
            and not self._busy)
        self.deploy_button.setTitle_(
            "Queued"
            if queue_pending else (
                "Deploy When Ready" if can_queue else "Deploy"
            )
        )
        test_count = len(self.validation_cases)
        self.run_validation_button.setTitle_(
            f"Run {test_count} Test{'s' if test_count != 1 else ''}")
        self.run_validation_button.setEnabled_(
            bool(test_count)
            and self.trigger in TRIGGERS
            and draft_ready
            and not self._busy
        )
        self.run_validation_button.setToolTip_(
            f"Run all {test_count} tests against the current draft with "
            f"{draft_compiler_label}."
            if draft_ready
            else f"Build {draft_compiler_label} for this draft first."
        )
        if self._busy:
            deploy_tooltip = "Wait for the current editor operation to finish."
        elif queue_pending:
            deploy_tooltip = (
                "This exact draft will deploy automatically after its compiler "
                "build finishes.")
        elif not basic_ready:
            deploy_tooltip = "Complete the rule name, trigger, and specification."
        elif not deploy_needed:
            deploy_tooltip = "No undeployed draft changes."
        elif can_queue:
            deploy_tooltip = (
                f"Queue this exact draft to deploy after "
                f"{draft_compiler_label} finishes building.")
        elif not draft_ready:
            deploy_tooltip = (
                f"Build {draft_compiler_label} for the current draft before "
                "deploying it.")
        elif stale_build_running:
            deploy_tooltip = (
                "Deploy these changes now. The compiler build for the "
                "previous revision will be discarded.")
        else:
            deploy_tooltip = "Deploy the current rule revision."
        self.deploy_button.setToolTip_(deploy_tooltip)
        self._programmatic = False
        if sync_text and self._shown:
            self._schedule_content_fit()

    @objc.python_method
    def _refresh_spec_guidance(self) -> None:
        level_check = rules_api.inspect_spec_levels(self.spec)
        self.spec_guidance_label.setStringValue_(
            (
                "Detected outputs: " + ", ".join(level_check["levels"])
                if level_check["ok"]
                else level_check["warning"]
            ))
        self.spec_guidance_label.setTextColor_(
            NSColor.secondaryLabelColor()
            if level_check["ok"] else NSColor.systemOrangeColor())

    @objc.python_method
    def update_finding_context(self, context: dict[str, Any] | None) -> None:
        self.finding_context = context
        self._refresh_finding_context()
        self._recalculate_key_loop()

    @objc.python_method
    def _refresh_finding_context(self) -> None:
        if not hasattr(self, "finding_callout"):
            return
        context = self.finding_context or {}
        finding = context.get("finding") or {}
        evaluation = context.get("evaluation") or {}
        input_text = str((evaluation.get("input") or {}).get("text", ""))
        preview = input_text[:320]
        if len(input_text) > len(preview):
            preview += "…"
        warning = (
            " · This finding used an older rule revision."
            if context.get("rule_changed") else "")
        self.finding_label.setStringValue_(
            f"{finding.get('severity', '').title()} finding{warning}\n"
            f"Input: {preview or '(no input)'}")
        self.finding_callout.setHidden_(not bool(context))

    @objc.python_method
    def copy_finding_input(self) -> None:
        evaluation = (self.finding_context or {}).get("evaluation") or {}
        text = str((evaluation.get("input") or {}).get("text", ""))
        board = NSPasteboard.generalPasteboard()
        board.clearContents()
        board.setString_forType_(text, NSPasteboardTypeString)

    @objc.python_method
    def show_finding(self) -> None:
        finding = (self.finding_context or {}).get("finding") or {}
        if self.manager and finding.get("id"):
            self.manager.show_finding(int(finding["id"]))

    @objc.python_method
    def editor_changed(self) -> None:
        if self._programmatic or self._busy:
            return
        self._capture()
        ok, source, _error = self._compose()
        self._current_source_hash = (
            revisions.hash_source(source) if ok else "")
        self._current_behavior_hash = (
            revisions.behavior_hash(source) if ok else "")
        self._source_dirty = (
            not ok or self._current_source_hash != self._saved_source_hash)
        self._cancel_queue_for_draft_change(
            "Draft changed after deployment was queued.")
        self._sync_draft_compiler_for_source()
        self._capture_validation_cases()
        self._validation_dirty = (
            json.dumps(self.validation_cases, sort_keys=True)
            != self._saved_validation_cases)
        self._invalidate_validation_results()
        if self._can_autosave_validation() and self._validation_dirty:
            self._schedule_validation_save()
            self._dirty = (
                self._source_dirty
                or self._coverage_dirty
                or self._compiler_dirty
            )
        else:
            self._dirty = (
                self._source_dirty
                or self._coverage_dirty
                or self._compiler_dirty
                or self._validation_dirty)
        self.rule["_deploy_failed"] = False
        self.window.setDocumentEdited_(self._dirty)
        self._fit_description_height()
        self._refresh_ui()

    @objc.python_method
    def _fit_description_height(self) -> None:
        if not hasattr(self, "spec_height_constraint"):
            return
        text = str(self.description_editor.string())
        lines = max(4, text.count("\n") + len(text) // 90 + 1)
        self.spec_height_constraint.setConstant_(
            min(260, max(100, lines * 18 + 24)))

    @objc.python_method
    def _schedule_content_fit(self) -> None:
        self._content_fit_generation += 1
        generation = self._content_fit_generation
        if self._content_fit_timer is not None:
            self._content_fit_timer.cancel()

        def fit() -> None:
            if (
                generation == self._content_fit_generation
                and self.window.isVisible()
            ):
                self._fit_window_to_content()

        self._content_fit_timer = _after_delay(0.08, fit)

    @objc.python_method
    def coverage_changed(self) -> None:
        if self._programmatic or self._busy:
            return
        self._cancel_queue_for_draft_change(
            "Project scope changed after deployment was queued.")
        current = {
            "mode": self.coverage_mode,
            "selected_projects": sorted(
                self.selected_projects
                if self.coverage_mode == "selected" else []),
        }
        self._coverage_dirty = current != self._active_coverage
        self._dirty = (
            self._source_dirty
            or self._coverage_dirty
            or self._compiler_dirty
            or self._validation_dirty
        )
        self.rule["_deploy_failed"] = False
        self.window.setDocumentEdited_(True)
        self._refresh_ui()

    @objc.python_method
    def trigger_changed(self, sender) -> None:
        selected = sender.selectedItem().representedObject()
        if selected == "__more__":
            self.show_more_triggers()
            return
        self.trigger = str(selected or "afterAgentResponse")
        self.input_pointer = ""
        self.trigger_error_label.setHidden_(True)
        self.editor_changed()
        self._refresh_ui()

    @objc.python_method
    def _validation_result_presentation(
        self, result: dict[str, Any]
    ) -> tuple[str, Any, str]:
        text = "Not run"
        color = NSColor.secondaryLabelColor()
        tooltip = ""
        if result.get("running"):
            text = "Running…"
        elif result:
            actual = str(result.get("actual") or "(empty)")
            if not result.get("valid_output", True):
                text = "Invalid output · Failed"
            else:
                text = (
                    f"Actual {actual} · "
                    f"{'Passed' if result.get('ok') else 'Failed'}")
            color = (
                NSColor.systemGreenColor()
                if result.get("ok") else NSColor.systemRedColor())
            provenance = " · ".join(
                value for value in (
                    str(result.get("compiler", "")),
                    str(result.get("compiler_snapshot", "")),
                )
                if value
            )
            tooltip = f"Raw result: {actual}"
            if provenance:
                tooltip += f"\nCompiler: {provenance}"
        return text, color, tooltip

    @objc.python_method
    def _refresh_validation_result_labels(self) -> None:
        for case in self.validation_cases:
            case_id = str(case.get("id", ""))
            label = self.validation_result_labels.get(case_id)
            if label is None:
                continue
            text, color, tooltip = self._validation_result_presentation(
                self._validation_results.get(case_id, {}))
            label.setStringValue_(text)
            label.setTextColor_(color)
            label.setToolTip_(tooltip or None)

    @objc.python_method
    def _render_validation_cases(self) -> None:
        for view in list(self.validation_stack.arrangedSubviews()):
            self.validation_stack.removeArrangedSubview_(view)
            view.removeFromSuperview()
        self.validation_controls = []
        self.validation_result_labels = {}
        for index, case in enumerate(self.validation_cases):
            input_field = NSTextField.alloc().init()
            input_field.setStringValue_(str(case.get("input", "")))
            input_field.setPlaceholderString_("Test input")
            input_field.setDelegate_(self._text_delegate)
            input_field.setMaximumNumberOfLines_(1)
            input_field.cell().setScrollable_(True)
            input_field.cell().setLineBreakMode_(
                NSLineBreakByTruncatingTail)
            input_field.setToolTip_(
                str(case.get("note") or case.get("input", "")))
            input_field.setContentHuggingPriority_forOrientation_(
                1, NSUserInterfaceLayoutOrientationHorizontal)
            input_field.setContentCompressionResistancePriority_forOrientation_(
                1, NSUserInterfaceLayoutOrientationHorizontal)
            output = NSPopUpButton.alloc().init()
            output.addItemsWithTitles_(
                ["OK", "INFO", "WARNING", "CRITICAL"])
            output.selectItemWithTitle_(
                str(case.get("expected", "WARNING")))
            self._wire(output, lambda _sender: self.validation_changed())
            remove = self._button(
                "",
                lambda _sender, value=index:
                    self.remove_validation_case(value),
                role="icon",
                accessibility=f"Remove validation case {index + 1}")
            set_button_symbol(
                remove, "trash", f"Remove validation case {index + 1}",
                fallback="Remove", point_size=11)
            remove.setToolTip_("Remove validation case")
            expand = self._button(
                "",
                lambda _sender, value=index:
                    self.edit_validation_input(value),
                role="icon",
                accessibility=f"Open validation case {index + 1}")
            set_button_symbol(
                expand, "arrow.up.left.and.arrow.down.right",
                f"Open validation case {index + 1}",
                fallback="Open", point_size=10)
            expand.setToolTip_("Open full input")
            result = self._validation_results.get(
                str(case.get("id", "")), {})
            result_text, result_color, result_tooltip = (
                self._validation_result_presentation(result))
            result_label = self._label(
                result_text, size=9.5, color=result_color)
            result_label.cell().setLineBreakMode_(
                NSLineBreakByTruncatingTail)
            result_label.setContentCompressionResistancePriority_forOrientation_(
                1, NSUserInterfaceLayoutOrientationHorizontal)
            if result_tooltip:
                result_label.setToolTip_(result_tooltip)
            row = self._stack(
                [input_field, output, result_label, expand, remove],
                vertical=False, spacing=8)
            _activate(
                input_field.widthAnchor().constraintGreaterThanOrEqualToConstant_(
                    300),
                output.widthAnchor().constraintEqualToConstant_(95),
                result_label.widthAnchor().constraintEqualToConstant_(170),
                expand.widthAnchor().constraintEqualToConstant_(28),
                remove.widthAnchor().constraintEqualToConstant_(28),
                row.heightAnchor().constraintEqualToConstant_(28),
            )
            self.validation_stack.addArrangedSubview_(row)
            self.validation_controls.append((input_field, output))
            self.validation_result_labels[
                str(case.get("id", ""))
            ] = result_label
        count = len(self.validation_cases)
        draft_compiler = self.resolved_draft_compiler()
        draft_ready = bool(
            not self.compiler_requires_build(draft_compiler)
            or self._draft_program_id()
        )
        self.run_validation_button.setTitle_(
            f"Run {count} Test{'s' if count != 1 else ''}")
        self.run_validation_button.setHidden_(count == 0)
        self.validation_actions_button.setHidden_(count == 0)
        self.validation_count_label.setHidden_(count == 0)
        self.validation_status.setHidden_(count == 0)
        self.validation_column_header.setHidden_(count == 0)
        self.validation_scroll.setHidden_(count == 0)
        self.run_validation_button.setEnabled_(
            bool(count)
            and self.trigger in TRIGGERS
            and draft_ready
            and not self._busy)
        visible = min(count, 5)
        self.validation_count_label.setStringValue_(
            f"({count})"
            + (f" · showing {visible}" if count > visible else ""))
        self.validation_height_constraint.setConstant_(
            0 if count == 0 else min(180, max(44, count * 34 + 8)))
        self.validation_document_height.setConstant_(
            0 if count == 0 else max(
                float(self.validation_height_constraint.constant()),
                float(count * 34 + 8),
            ))
        self.validation_document.layoutSubtreeIfNeeded()
        if hasattr(self, "compiler_action_button"):
            self._recalculate_key_loop()

    @objc.python_method
    def _capture_validation_cases(self) -> None:
        existing_ids = [
            str(case.get("id", "")) for case in self.validation_cases]
        existing_notes = [
            str(case.get("note", "")) for case in self.validation_cases]
        self.validation_cases = []
        for index, (input_field, output) in enumerate(
            self.validation_controls
        ):
            input_text = str(input_field.stringValue())
            if not input_text:
                continue
            self.validation_cases.append({
                "id": (
                    existing_ids[index]
                    if index < len(existing_ids) and existing_ids[index]
                    else secrets.token_hex(8)
                ),
                "input": input_text,
                "expected": str(output.titleOfSelectedItem()),
                "note": (
                    existing_notes[index]
                    if index < len(existing_notes) else ""),
            })

    @objc.python_method
    def _validation_cache_key(self, result: dict[str, Any]) -> str:
        return "\x00".join((
            str(result.get("spec_hash", "")),
            str(result.get("compiler", "")),
            str(result.get("compiler_snapshot", "")),
            str(result.get("program_id", "")),
            str(result.get("case_hash", "")),
        ))

    @objc.python_method
    def _cache_validation_results(
        self, results: list[dict[str, Any]]
    ) -> None:
        for result in results:
            if not result.get("case_hash") or not result.get("spec_hash"):
                continue
            self._validation_result_cache[
                self._validation_cache_key(result)
            ] = dict(result)

    @objc.python_method
    def _reconcile_validation_results(self) -> None:
        spec_hash = validation_store.spec_fingerprint(self.spec)
        compiler = str(self._validation_target.get("compiler", ""))
        snapshot = str(
            self._validation_target.get("compiler_snapshot", ""))
        program_id = str(self._validation_target.get("program_id", ""))
        current = dict(self._validation_results)
        reconciled: dict[str, dict[str, Any]] = {}
        for case in self.validation_cases:
            case_id = str(case.get("id", ""))
            case_hash = validation_store.case_fingerprint(case)
            running = current.get(case_id) or {}
            if (
                running.get("running")
                and running.get("spec_hash") == spec_hash
                and running.get("case_hash") == case_hash
            ):
                reconciled[case_id] = running
                continue
            key = "\x00".join((
                spec_hash, compiler, snapshot, program_id, case_hash))
            cached = self._validation_result_cache.get(key)
            if cached is None and not program_id:
                candidates = [
                    value for value in self._validation_result_cache.values()
                    if value.get("spec_hash") == spec_hash
                    and (
                        not compiler
                        or value.get("compiler") == compiler
                    )
                    and value.get("compiler_snapshot") == snapshot
                    and value.get("case_hash") == case_hash
                ]
                cached = max(
                    candidates,
                    key=lambda value: float(value.get("ran_at", 0)),
                    default=None,
                )
            if cached is not None:
                reconciled[case_id] = {
                    **cached,
                    **case,
                    "case_hash": case_hash,
                }
        self._validation_results = reconciled
        self._update_validation_summary()

    @objc.python_method
    def _update_validation_summary(self) -> None:
        completed = [
            result for result in self._validation_results.values()
            if not result.get("running")
        ]
        if any(
            result.get("running")
            for result in self._validation_results.values()
        ):
            return
        if not completed:
            self.validation_status.setStringValue_(
                "Not run for current specification.")
            self.validation_status.setTextColor_(
                NSColor.systemOrangeColor())
            return
        passed = sum(1 for result in completed if result.get("ok"))
        failed = len(completed) - passed
        not_run = max(0, len(self.validation_cases) - len(completed))
        compiler = str(
            completed[0].get("compiler")
            or self._validation_target.get("compiler", ""))
        latest = max(
            float(result.get("ran_at", 0)) for result in completed)
        parts = [f"{passed}/{len(completed)} passed"]
        if not_run:
            parts.append(f"{not_run} not run")
        parts.append(self.compiler_label(compiler))
        if latest:
            parts.append(time.strftime("%-I:%M %p", time.localtime(latest)))
        self.validation_status.setStringValue_(" · ".join(parts))
        self.validation_status.setTextColor_(
            NSColor.systemRedColor()
            if failed else (
                NSColor.systemOrangeColor()
                if not_run else NSColor.systemGreenColor()
            )
        )

    @objc.python_method
    def _invalidate_validation_results(self) -> None:
        self._reconcile_validation_results()
        self._refresh_validation_result_labels()

    @objc.python_method
    def edit_validation_input(self, index: int) -> None:
        self._capture_validation_cases()
        if not 0 <= index < len(self.validation_cases):
            return
        scroll = NSScrollView.alloc().initWithFrame_(
            NSMakeRect(0, 0, 560, 180))
        scroll.setHasVerticalScroller_(True)
        editor = NSTextView.alloc().initWithFrame_(
            NSMakeRect(0, 0, 540, 180))
        editor.setFont_(NSFont.monospacedSystemFontOfSize_weight_(11, 0))
        editor.setString_(self.validation_cases[index]["input"])
        scroll.setDocumentView_(editor)
        alert = NSAlert.alloc().init()
        alert.setMessageText_(f"Validation case {index + 1}")
        note = str(self.validation_cases[index].get("note", ""))
        alert.setInformativeText_(
            note or "Edit the exact input used for validation.")
        alert.setAccessoryView_(scroll)
        alert.addButtonWithTitle_("Apply")
        alert.addButtonWithTitle_("Cancel")

        def completed(response):
            if response != NSAlertFirstButtonReturn:
                return
            input_text = str(editor.string())
            if not input_text:
                return
            self.validation_cases[index]["input"] = input_text
            self._render_validation_cases()
            self.validation_changed()

        alert.beginSheetModalForWindow_completionHandler_(
            self.window, completed)

    @objc.python_method
    def validation_changed(self) -> None:
        self._cancel_queue_for_draft_change(
            "Validation cases changed after deployment was queued.")
        self._capture_validation_cases()
        self._validation_dirty = (
            json.dumps(self.validation_cases, sort_keys=True)
            != self._saved_validation_cases)
        self._invalidate_validation_results()
        if self._can_autosave_validation():
            self._dirty = self._source_dirty or self._coverage_dirty
            self._schedule_validation_save()
        else:
            self._dirty = (
                self._source_dirty
                or self._coverage_dirty
                or self._validation_dirty)
            self.window.setDocumentEdited_(True)
            self.validation_status.setStringValue_(
                "Saved with the first draft or deployment.")
        self._refresh_ui()
        self._schedule_content_fit()

    @objc.python_method
    def add_validation_case(self) -> None:
        self._cancel_queue_for_draft_change(
            "Validation cases changed after deployment was queued.")
        self._capture_validation_cases()
        self.validation_cases.append({
            "id": secrets.token_hex(8),
            "input": "",
            "expected": "WARNING",
            "note": "",
        })
        self._render_validation_cases()
        if self.validation_controls:
            self.window.makeFirstResponder_(
                self.validation_controls[-1][0])
        _on_main(self._scroll_validation_to_bottom)

    @objc.python_method
    def _scroll_validation_to_bottom(self) -> None:
        self.validation_document.layoutSubtreeIfNeeded()
        clip = self.validation_scroll.contentView()
        maximum = max(
            0.0,
            float(self.validation_document.frame().size.height)
            - float(clip.bounds().size.height),
        )
        clip.scrollToPoint_((0, maximum))
        self.validation_scroll.reflectScrolledClipView_(clip)

    @objc.python_method
    def remove_validation_case(self, index: int) -> None:
        self._cancel_queue_for_draft_change(
            "Validation cases changed after deployment was queued.")
        self._capture_validation_cases()
        if 0 <= index < len(self.validation_cases):
            removed = self.validation_cases.pop(index)
            self._last_removed_validation = (index, removed)
            self.validation_undo_button.setHidden_(False)
            self._validation_dirty = True
            self._invalidate_validation_results()
            self._render_validation_cases()
            if self._can_autosave_validation():
                self._persist_validation_cases()
            else:
                self.validation_changed()

    @objc.python_method
    def undo_remove_validation_case(self) -> None:
        self._cancel_queue_for_draft_change(
            "Validation cases changed after deployment was queued.")
        if not self._last_removed_validation:
            return
        index, removed = self._last_removed_validation
        if isinstance(removed, list):
            self.validation_cases = list(removed)
        else:
            self.validation_cases.insert(
                min(int(index), len(self.validation_cases)), removed)
        self._last_removed_validation = None
        self.validation_undo_button.setHidden_(True)
        self._invalidate_validation_results()
        self._render_validation_cases()
        if self._can_autosave_validation():
            self._persist_validation_cases()
        else:
            self.validation_changed()

    @objc.python_method
    def show_validation_actions(self, sender) -> None:
        menu = NSMenu.alloc().initWithTitle_("Validation actions")
        item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Remove all cases", "invoke:", "")
        self._wire(item, lambda _sender: self.remove_all_validation_cases())
        item.setEnabled_(bool(self.validation_cases))
        menu.addItem_(item)
        menu.popUpMenuPositioningItem_atLocation_inView_(
            None, (0, sender.bounds().size.height), sender)

    @objc.python_method
    def remove_all_validation_cases(self) -> None:
        self._cancel_queue_for_draft_change(
            "Validation cases changed after deployment was queued.")
        self._capture_validation_cases()
        if not self.validation_cases:
            return
        self._last_removed_validation = (0, list(self.validation_cases))
        self.validation_cases = []
        self.validation_undo_button.setHidden_(False)
        self._invalidate_validation_results()
        self._render_validation_cases()
        if self._can_autosave_validation():
            self._persist_validation_cases()
        else:
            self.validation_changed()

    @objc.python_method
    def _can_autosave_validation(self) -> bool:
        return bool((self.rule.get("definition") or {}).get("source_path"))

    @objc.python_method
    def _schedule_validation_save(self) -> None:
        self._validation_save_generation += 1
        generation = self._validation_save_generation
        self.validation_status.setStringValue_("Saving…")
        self.validation_status.setTextColor_(
            NSColor.secondaryLabelColor())

        def save() -> None:
            if generation == self._validation_save_generation:
                self._persist_validation_cases()

        _after_delay(0.4, save)

    @objc.python_method
    def _persist_validation_cases(self) -> None:
        self._capture_validation_cases()
        self.validation_status.setStringValue_("Saving…")
        self.validation_status.setTextColor_(
            NSColor.secondaryLabelColor())

        def completed(result):
            def apply():
                if result.get("ok"):
                    self.validation_cases = list(
                        result.get("cases") or self.validation_cases)
                    self._saved_validation_cases = json.dumps(
                        self.validation_cases, sort_keys=True)
                    self._validation_dirty = False
                    self._dirty = (
                        self._source_dirty
                        or self._coverage_dirty
                        or self._compiler_dirty
                    )
                    self.window.setDocumentEdited_(self._dirty)
                    if self._validation_results:
                        self._update_validation_summary()
                    else:
                        self.validation_status.setStringValue_("Saved")
                        self.validation_status.setTextColor_(
                            NSColor.systemGreenColor())
                else:
                    self.validation_status.setStringValue_(
                        result.get("error", "Could not save validation cases."))
                    self.validation_status.setTextColor_(
                        NSColor.systemRedColor())
            _on_main(apply)

        self.model.perform({
            "type": "save_validation_cases",
            "rule_id": self.rule_id,
            "project_root": self.project_root,
            "validation_cases": self.validation_cases,
        }, completed)

    @objc.python_method
    def run_validation_cases(self) -> None:
        self._capture_validation_cases()
        if not self.validation_cases:
            return
        ok, source, error = self._compose()
        if not ok:
            self._deployment_failed(error)
            return
        run_key = secrets.token_hex(8)
        self._validation_run_key = run_key
        spec_hash = validation_store.spec_fingerprint(self.spec)
        self._validation_results = {
            str(case.get("id", "")): {
                "running": True,
                "spec_hash": spec_hash,
                "case_hash": validation_store.case_fingerprint(case),
            }
            for case in self.validation_cases
        }
        self.validation_status.setStringValue_(
            "Preparing the validation program and running tests…")
        self.validation_status.setTextColor_(
            NSColor.secondaryLabelColor())
        self._refresh_validation_result_labels()
        self._set_busy(True, busy_label="Running validation")

        def completed(result):
            def apply():
                self._set_busy(False)
                if run_key != self._validation_run_key:
                    return
                if not result.get("ok"):
                    self._validation_results = {}
                    self._validation_run_key = ""
                    self._reconcile_validation_results()
                    self.validation_status.setStringValue_(
                        result.get("error", "Validation failed to run."))
                    self.validation_status.setTextColor_(
                        NSColor.systemRedColor())
                    self._refresh_validation_result_labels()
                    return
                validation = result.get("validation") or {}
                self._validation_target = dict(
                    result.get("target")
                    or self._validation_target
                    or {
                        "compiler": self.active_compiler,
                        "compiler_snapshot": self.active_compiler_snapshot,
                    }
                )
                validation_results = []
                for item in validation.get("results") or []:
                    value = dict(item)
                    value.setdefault("spec_hash", spec_hash)
                    value.setdefault(
                        "case_hash",
                        validation_store.case_fingerprint(value),
                    )
                    value.setdefault(
                        "compiler",
                        str(self._validation_target.get("compiler", "")),
                    )
                    value.setdefault(
                        "compiler_snapshot",
                        str(self._validation_target.get(
                            "compiler_snapshot", "")),
                    )
                    value.setdefault("ran_at", time.time())
                    validation_results.append(value)
                self._cache_validation_results(validation_results)
                self._validation_results = {}
                self._validation_run_key = ""
                self._reconcile_validation_results()
                timing = result.get("timing") or {}
                if timing:
                    summary = str(self.validation_status.stringValue())
                    summary += (
                        f" · compile {float(timing.get('compile_ms', 0)) / 1000:.1f}s"
                        f" · run {float(timing.get('run_ms', 0)) / 1000:.1f}s"
                    )
                    self.validation_status.setStringValue_(summary)
                self._refresh_validation_result_labels()
            _on_main(apply)

        self.model.perform({
            "type": "validate_rule_cases",
            "rule_id": self.rule_id,
            "project_root": self.project_root,
            "source": source,
            "validation_cases": self.validation_cases,
            "compiler": self.resolved_draft_compiler(),
            "compiler_snapshot": self.draft_compiler_snapshot,
            "program_id": self._draft_program_id(),
        }, completed, timeout=180)

    @objc.python_method
    def reload_validation_results(self) -> None:
        self._capture_validation_cases()
        if not self.validation_cases:
            return
        ok, source, _error = self._compose()
        if not ok:
            return
        self._validation_load_generation += 1
        generation = self._validation_load_generation

        def completed(result):
            def apply():
                if generation != self._validation_load_generation:
                    return
                self._validation_results_loaded = True
                if not result.get("ok"):
                    return
                self._validation_target = dict(result.get("target") or {})
                validation = result.get("validation") or {}
                self._cache_validation_results(
                    list(validation.get("results") or []))
                self._reconcile_validation_results()
                self._refresh_validation_result_labels()
            _on_main(apply)

        request = {
            "type": "cached_validation_results",
            "rule_id": self.rule_id,
            "project_root": self.project_root,
            "source": source,
            "validation_cases": self.validation_cases,
            "compiler": self.resolved_draft_compiler(),
            "compiler_snapshot": self.draft_compiler_snapshot,
            "program_id": self._draft_program_id(),
        }
        if hasattr(self.model, "query"):
            self.model.query(request, completed, timeout=10)
        else:
            self.model.perform(request, completed, timeout=10)

    @objc.python_method
    def show_more_triggers(self) -> None:
        accessory = NSView.alloc().initWithFrame_(
            NSMakeRect(0, 0, 520, 92))
        search = NSSearchField.alloc().initWithFrame_(
            NSMakeRect(0, 62, 520, 26))
        search.setPlaceholderString_("Search triggers")
        chooser = NSPopUpButton.alloc().initWithFrame_(
            NSMakeRect(0, 28, 520, 28))
        self._more_trigger_options = [
            definition for definition in ORDERED_TRIGGERS
            if not definition.common
        ]
        self._more_trigger_chooser = chooser
        self._populate_more_triggers("")
        details = self._label(
            "Search by action, Cursor hook, or JSON Pointer.",
            size=9.5, color=NSColor.secondaryLabelColor())
        details.setFrame_(NSMakeRect(2, 2, 516, 20))
        accessory.addSubview_(search)
        accessory.addSubview_(chooser)
        accessory.addSubview_(details)
        self._wire(
            search,
            lambda sender: self._populate_more_triggers(
                str(sender.stringValue())))
        alert = NSAlert.alloc().init()
        alert.setMessageText_("Choose a trigger")
        alert.setInformativeText_(
            "Each trigger reads exactly one documented Cursor field.")
        alert.setAccessoryView_(accessory)
        alert.addButtonWithTitle_("Use Trigger")
        alert.addButtonWithTitle_("Cancel")

        def completed(response):
            if response == NSAlertFirstButtonReturn:
                if chooser.selectedItem() is None:
                    return
                self.trigger = str(
                    chooser.selectedItem().representedObject())
                self.input_pointer = ""
                self.editor_changed()
            else:
                self._refresh_ui()

        alert.beginSheetModalForWindow_completionHandler_(
            self.window, completed)

    @objc.python_method
    def _populate_more_triggers(self, query: str) -> None:
        chooser = self._more_trigger_chooser
        chooser.removeAllItems()
        normalized = query.strip().lower()
        for definition in self._more_trigger_options:
            searchable = (
                f"{definition.label} {definition.hook} "
                f"{definition.input_pointer} {definition.category}").lower()
            if normalized and normalized not in searchable:
                continue
            chooser.addItemWithTitle_(
                f"[{definition.category}] {definition.label} — Input: "
                f"{definition.hook} {definition.input_pointer}")
            chooser.lastItem().setRepresentedObject_(definition.hook)

    @objc.python_method
    def show_input_mapping(self) -> None:
        definition = TRIGGERS.get(self.trigger)
        default = definition.input_pointer if definition else ""
        field = NSTextField.alloc().initWithFrame_(
            NSMakeRect(0, 0, 460, 24))
        field.setStringValue_(self.input_pointer or default)
        field.setPlaceholderString_(default)
        alert = NSAlert.alloc().init()
        alert.setMessageText_("Advanced input mapping")
        alert.setInformativeText_(
            f"Default: {self.trigger} {default}. Clear the field to restore "
            "the default mapping.")
        alert.setAccessoryView_(field)
        alert.addButtonWithTitle_("Apply")
        alert.addButtonWithTitle_("Cancel")

        def completed(response):
            if response != NSAlertFirstButtonReturn:
                return
            pointer = str(field.stringValue()).strip()
            if pointer and not pointer.startswith("/"):
                self.diagnostics_label.setStringValue_(
                    "Input JSON Pointer must start with '/'.")
                self.diagnostics_label.setHidden_(False)
                return
            self.input_pointer = "" if pointer == default else pointer
            self.editor_changed()

        alert.beginSheetModalForWindow_completionHandler_(
            self.window, completed)

    @objc.python_method
    def set_coverage_mode(self, mode: str) -> None:
        self.coverage_mode = mode
        self._scope_confirmed = True
        self.coverage_changed()
        if mode == "selected" and not self.selected_projects:
            self.show_projects_sheet()

    @objc.python_method
    def show_info(self, sender, title: str, body: str) -> None:
        controller = NSViewController.alloc().init()
        view = NSView.alloc().initWithFrame_(NSMakeRect(0, 0, 300, 132))
        heading = self._label(title, size=13, bold=True)
        heading.setFrame_(NSMakeRect(14, 14, 272, 20))
        copy = self._label(body, size=11, lines=6)
        copy.setFrame_(NSMakeRect(14, 40, 272, 78))
        view.addSubview_(heading)
        view.addSubview_(copy)
        controller.setView_(view)
        popover = NSPopover.alloc().init()
        popover.setBehavior_(NSPopoverBehaviorTransient)
        popover.setContentSize_(NSMakeSize(300, 132))
        popover.setContentViewController_(controller)
        popover.showRelativeToRect_ofView_preferredEdge_(
            sender.bounds(), sender, NSMinYEdge)
        self._info_popover = popover

    @objc.python_method
    def show_projects_sheet(
        self, on_confirm: Callable[[], None] | None = None
    ) -> None:
        alert = NSAlert.alloc().init()
        alert.setMessageText_("Where should this rule run?")
        alert.setInformativeText_(
            "All projects includes future projects. Selected projects runs "
            "only where explicitly checked.")
        accessory = NSView.alloc().initWithFrame_(
            NSMakeRect(0, 0, 430, 340))
        all_radio = NSButton.alloc().initWithFrame_(
            NSMakeRect(0, 312, 190, 24))
        all_radio.setButtonType_(NSButtonTypeRadio)
        all_radio.setTitle_("All projects")
        selected_radio = NSButton.alloc().initWithFrame_(
            NSMakeRect(200, 312, 190, 24))
        selected_radio.setButtonType_(NSButtonTypeRadio)
        selected_radio.setTitle_("Selected projects")
        all_radio.setState_(
            NSControlStateValueOn
            if self.coverage_mode == "all" else NSControlStateValueOff)
        selected_radio.setState_(
            NSControlStateValueOn
            if self.coverage_mode == "selected" else NSControlStateValueOff)
        self._wire(
            all_radio,
            lambda _sender: (
                all_radio.setState_(NSControlStateValueOn),
                selected_radio.setState_(NSControlStateValueOff),
            ),
            key_view=False,
        )
        self._wire(
            selected_radio,
            lambda _sender: (
                selected_radio.setState_(NSControlStateValueOn),
                all_radio.setState_(NSControlStateValueOff),
            ),
            key_view=False,
        )
        accessory.addSubview_(all_radio)
        accessory.addSubview_(selected_radio)
        search = NSSearchField.alloc().initWithFrame_(
            NSMakeRect(0, 276, 430, 26))
        search.setPlaceholderString_("Search projects")
        accessory.addSubview_(search)
        project_scroll = NSScrollView.alloc().initWithFrame_(
            NSMakeRect(0, 0, 430, 266))
        project_scroll.setHasVerticalScroller_(True)
        project_scroll.setDrawsBackground_(False)
        document_height = max(266, len(self.projects) * 26)
        project_document = RAPFlippedView.alloc().initWithFrame_(
            NSMakeRect(0, 0, 414, document_height))
        project_scroll.setDocumentView_(project_document)
        accessory.addSubview_(project_scroll)
        checks: list[tuple[NSButton, str, str]] = []
        for index, project in enumerate(self.projects):
            project_name = project.get("name") or Path(project["path"]).name
            check = NSButton.alloc().initWithFrame_(
                NSMakeRect(0, index * 26, 400, 24))
            check.setButtonType_(NSButtonTypeSwitch)
            check.setTitle_(project_name)
            check.setState_(
                NSControlStateValueOn
                if project["path"] in self.selected_projects
                else NSControlStateValueOff)
            project_document.addSubview_(check)
            checks.append((check, project["path"], project_name))

        def filter_projects(sender):
            query = str(sender.stringValue()).strip().lower()
            visible = [
                item for item in checks
                if not query or query in item[2].lower()
                or query in item[1].lower()
            ]
            height = max(266, len(visible) * 26)
            project_document.setFrameSize_(NSMakeSize(414, height))
            visible_ids = {id(item[0]) for item in visible}
            row = 0
            for check, _path, _name in checks:
                shown = id(check) in visible_ids
                check.setHidden_(not shown)
                if shown:
                    check.setFrameOrigin_((0, row * 26))
                    row += 1

        self._wire(search, filter_projects, key_view=False)
        alert.setAccessoryView_(accessory)
        alert.addButtonWithTitle_("Apply")
        alert.addButtonWithTitle_("Cancel")

        def completed(response):
            if response != NSAlertFirstButtonReturn:
                return
            self.coverage_mode = (
                "all"
                if all_radio.state() == NSControlStateValueOn
                and selected_radio.state() != NSControlStateValueOn
                else "selected"
            )
            self.selected_projects = [
                path for check, path, _name in checks
                if check.state() == NSControlStateValueOn
            ]
            self._scope_confirmed = True
            self.coverage_changed()
            if on_confirm:
                on_confirm()

        alert.beginSheetModalForWindow_completionHandler_(
            self.window, completed)

    @objc.python_method
    def show_advanced_menu(self, sender) -> None:
        menu = NSMenu.alloc().initWithTitle_("Advanced")
        for title, callback in (
            ("Compilation…", self.show_compilation),
            ("Evaluation History…", self.show_evaluation_history),
            ("Input Mapping…", self.show_input_mapping),
            ("View Compiled Spec…", self.show_compiled_spec),
            ("View Python…", self.show_advanced),
        ):
            item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                title, "invoke:", "")
            self._wire(item, lambda _item, fn=callback: fn())
            menu.addItem_(item)
        menu.popUpMenuPositioningItem_atLocation_inView_(
            None, (0, sender.bounds().size.height), sender)

    @objc.python_method
    def show_evaluation_history(self) -> None:
        from .evaluation_history import EvaluationHistoryManager
        if not hasattr(self, "_evaluation_history_manager"):
            self._evaluation_history_manager = EvaluationHistoryManager(
                self.model,
                self.manager.show_finding if self.manager else None,
                lambda _rule_id, _project_root:
                    self.reload_validation_cases())
        self._evaluation_history_manager.open(
            self.rule_id, self.name, self.project_root)

    @objc.python_method
    def _queue_is_pending(self) -> bool:
        return str(self._deployment_queue.get("status", "")) in (
            "waiting_for_build", "building", "checking", "validating", "deploying")

    @objc.python_method
    def compiler_action(self) -> None:
        if not self._queue_is_pending():
            self.show_compilation()
            return
        alert = NSAlert.alloc().init()
        alert.setMessageText_("Cancel queued deployment?")
        alert.setInformativeText_(
            "The compiler build may continue, but this draft will no longer "
            "deploy automatically.")
        alert.addButtonWithTitle_("Keep Queued")
        alert.addButtonWithTitle_("Cancel Deployment")

        def completed(response):
            if response == NSAlertSecondButtonReturn:
                self.cancel_queued_deployment("Cancelled by user.")

        alert.beginSheetModalForWindow_completionHandler_(
            self.window, completed)

    @objc.python_method
    def reload_deployment_queue(self) -> None:
        def completed(result):
            if result.get("ok"):
                self._deployment_queue_poll_failures = 0
                _on_main(lambda: self._apply_deployment_queue(
                    dict(result.get("queue") or {})))
            elif self._queue_is_pending():
                self._recover_deployment_queue_poll()

        request = {
            "type": "deployment_queue_status",
            "rule_id": self.rule_id,
        }
        if hasattr(self.model, "query"):
            self.model.query(request, completed, timeout=10)
        else:
            self.model.perform(request, completed, timeout=10)

    @objc.python_method
    def _recover_deployment_queue_poll(self) -> None:
        self._deployment_queue_poll_failures += 1

        def recover():
            result = None
            if ipc.ensure_daemon(wait=8.0):
                result = ipc.send_request({
                    "type": "deployment_queue_status",
                    "rule_id": self.rule_id,
                    "deployment_id": str(
                        self._deployment_queue.get("id", "")),
                }, timeout=10)

            def apply():
                if result and result.get("ok"):
                    self._deployment_queue_poll_failures = 0
                    self._apply_deployment_queue(
                        dict(result.get("queue") or {}))
                elif self._queue_is_pending():
                    self._schedule_deployment_queue_poll()

            _on_main(apply)

        worker = threading.Thread(
            target=recover,
            name="rap-queue-poll-recovery",
            daemon=True,
        )
        self._deployment_queue_poll_recovery_thread = worker
        worker.start()

    @objc.python_method
    def _apply_deployment_queue(self, value: dict[str, Any]) -> None:
        was_pending = self._queue_is_pending()
        self._deployment_queue = dict(value)
        status = str(value.get("status", ""))
        if status in (
            "waiting_for_build", "building", "checking", "validating", "deploying"
        ):
            self._clear_diagnostics()
            self._schedule_deployment_queue_poll()
        elif status in ("succeeded", "failed", "cancelled"):
            self._pending_deployment_id = ""
            if self._deployment_queue_poll_timer:
                self._deployment_queue_poll_timer.cancel()
                self._deployment_queue_poll_timer = None
            terminal_key = f"{value.get('id')}:{status}"
            recent = (
                time.time() - float(value.get("finished_at", 0) or 0) < 30
            )
            if (
                terminal_key != self._notified_queue_terminal
                and (was_pending or recent)
            ):
                self._notified_queue_terminal = terminal_key
                title = (
                    "Rule deployed"
                    if status == "succeeded"
                    else "Queued deployment needs attention"
                )
                body = (
                    f"{self.name} deployed successfully."
                    if status == "succeeded"
                    else str(value.get("error") or "Deployment did not finish.")
                )
                notification = NSUserNotification.alloc().init()
                notification.setTitle_(title)
                notification.setInformativeText_(body)
                NSUserNotificationCenter.defaultUserNotificationCenter(
                ).deliverNotification_(notification)
            if status == "succeeded":
                self._clear_diagnostics()
                result = value.get("result") or {}
                active = result.get("active") or {}
                rule = result.get("rule") or {}
                self.rule.update(rule)
                self.rule["new_draft"] = False
                self._active_hash = str(active.get("source_hash", ""))
                self._active_behavior_hash = str(
                    active.get("behavior_hash")
                    or value.get("behavior_hash")
                    or self._current_behavior_hash)
                self.active_compiler = str(active.get("compiler", ""))
                self.active_compiler_snapshot = str(
                    active.get("compiler_snapshot", ""))
                self.active_program_id = str(active.get("program_id", ""))
                self.active_compiler_mode = str(
                    active.get("compiler_mode")
                    or revisions.AUTOMATIC_COMPILER_MODE)
                self.active_artifacts = dict(active.get("artifacts") or {})
                self.compiler_mode = self.active_compiler_mode
                self._draft_compiler_explicit = (
                    self.compiler_mode == revisions.EXPLICIT_COMPILER_MODE)
                self._sync_draft_compiler_for_source()
                self._compiler_dirty = False
                self._source_dirty = False
                self._coverage_dirty = False
                self._validation_dirty = False
                self._dirty = False
                self.full_source = str(
                    rule.get("source") or self.full_source)
                self._working_hash = str(
                    rule.get("working_hash") or self._active_hash)
                self._definition_hash = str(
                    (rule.get("definition") or {}).get(
                        "source_hash", self._active_hash))
                self._saved_source_hash = revisions.hash_source(
                    self.full_source)
                self._current_source_hash = self._saved_source_hash
                self._current_behavior_hash = revisions.behavior_hash(
                    self.full_source)
                coverage = result.get("coverage") or {}
                self.coverage_mode = str(
                    coverage.get("mode", self.coverage_mode))
                self.selected_projects = list(
                    coverage.get("selected_projects") or [])
                self._active_coverage = {
                    "mode": str(
                        coverage.get("mode", self.coverage_mode)),
                    "selected_projects": sorted(
                        coverage.get("selected_projects") or []),
                }
                self.window.setDocumentEdited_(False)
                self.diagnostics_label.setStringValue_(
                    "✓ Deployed in the background.")
                self.diagnostics_label.setTextColor_(
                    NSColor.systemGreenColor())
                self.diagnostics_label.setHidden_(False)
                if self.manager:
                    self.manager.changed(result)
            elif status == "failed":
                self._set_compilation_message(
                    str(value.get("error") or "Queued deployment failed."),
                    str(value.get("id", "")),
                )
        self._refresh_ui()

    @objc.python_method
    def _schedule_deployment_queue_poll(self) -> None:
        if self._deployment_queue_poll_timer:
            self._deployment_queue_poll_timer.cancel()

        def poll():
            self.reload_deployment_queue()

        delay = min(
            30.0,
            2.0 * (2 ** min(self._deployment_queue_poll_failures, 4)),
        )
        self._deployment_queue_poll_timer = _after_delay(delay, poll)

    @objc.python_method
    def cancel_queued_deployment(self, reason: str) -> None:
        if not self._queue_is_pending():
            return
        self._deployment_queue["status"] = "cancelling"
        self._refresh_ui()

        def completed(result):
            if result.get("ok"):
                _on_main(lambda: self._apply_deployment_queue(
                    dict(result.get("queue") or {})))
            else:
                def failed():
                    self._set_compilation_message(
                        result.get("error", "Could not cancel deployment."))
                    self.reload_deployment_queue()
                _on_main(failed)

        self.model.perform({
            "type": "cancel_queued_deployment",
            "rule_id": self.rule_id,
            "reason": reason,
        }, completed, timeout=10)

    @objc.python_method
    def _cancel_queue_for_draft_change(self, reason: str) -> None:
        self._draft_generation += 1
        if self._queue_is_pending():
            self.cancel_queued_deployment(reason)

    @objc.python_method
    def reload_compiler_catalog(
        self, *, refresh: bool = False, then: Callable[[], None] | None = None
    ) -> None:
        request = {"type": "compiler_catalog", "refresh": refresh}

        def completed(result):
            def apply():
                self._compiler_catalog_attempted = True
                if result.get("ok"):
                    self.compiler_catalog = list(
                        result.get("compilers") or [])
                    self.compiler_catalog_cached = bool(result.get("cached"))
                    self.compiler_catalog_offline = bool(result.get("offline"))
                    self.compiler_catalog_fetched_at = float(
                        result.get("fetched_at") or 0)
                    self._sync_draft_compiler_for_source()
                    self._validation_target = {
                        "compiler": self.resolved_draft_compiler(),
                        "compiler_snapshot": self.draft_compiler_snapshot,
                        "program_id": self._draft_program_id(),
                    }
                    self._reconcile_validation_results()
                    self._refresh_validation_result_labels()
                    self._refresh_ui()
                    if self._validation_results:
                        self._update_validation_summary()
                if then:
                    then()
            _on_main(apply)

        if hasattr(self.model, "query"):
            self.model.query(request, completed, timeout=10)
        else:
            self.model.perform(request, completed, timeout=10)

    @objc.python_method
    def compiler_info(self, name: str = "") -> dict[str, Any]:
        if name:
            return next(
                (
                    dict(item) for item in self.compiler_catalog
                    if str(item.get("name", "")) == name
                ),
                {"name": name, "description": name},
            )
        return next(
            (
                dict(item) for item in self.compiler_catalog
                if item.get("default")
            ),
            {"name": "", "description": "Server default", "default": True},
        )

    @objc.python_method
    def compiler_label(self, name: str = "") -> str:
        info = self.compiler_info(name)
        description = str(info.get("description") or info.get("name") or "")
        return description.split("—", 1)[0].strip() or "Server default"

    @objc.python_method
    def automatic_base_compiler_info(self) -> dict[str, Any]:
        default = self.compiler_info()
        if (
            default.get("compiler_kind") != "finetune_lora"
            and default.get("supports_local_sdk", True)
        ):
            return default
        return next(
            (
                dict(item) for item in self.compiler_catalog
                if item.get("compiler_kind") == "mapper_lora"
                and item.get("supports_local_sdk", True)
            ),
            next(
                (
                    dict(item) for item in self.compiler_catalog
                    if item.get("compiler_kind") != "finetune_lora"
                    and item.get("supports_local_sdk", True)
                ),
                default,
            ),
        )

    @objc.python_method
    def resolved_active_compiler(self) -> str:
        return str(
            self.active_compiler or self.compiler_info().get("name", ""))

    @objc.python_method
    def resolved_draft_compiler(self) -> str:
        if self.compiler_mode == revisions.AUTOMATIC_COMPILER_MODE:
            return str(self.automatic_base_compiler_info().get("name", ""))
        return str(
            self.draft_compiler
            or self.compiler_info().get("name", ""))

    @objc.python_method
    def _artifact_for_compiler(self, compiler: str) -> dict[str, Any]:
        if self._current_behavior_hash != self._active_behavior_hash:
            return {}
        candidates = [
            dict(item)
            for item in self.active_artifacts.values()
            if isinstance(item, dict)
            and str(item.get("compiler", "")) == compiler
            and item.get("program_id")
        ]
        return max(
            candidates,
            key=lambda item: float(item.get("created_at", 0) or 0),
            default={},
        )

    @objc.python_method
    def _compiler_selection_dirty(self) -> bool:
        if not self._active_hash:
            return False
        if self.compiler_mode != self.active_compiler_mode:
            return True
        if self.compiler_mode == revisions.AUTOMATIC_COMPILER_MODE:
            return False
        return self.resolved_draft_compiler() != self.resolved_active_compiler()

    @objc.python_method
    def compiler_requires_build(self, name: str) -> bool:
        return (
            str(self.compiler_info(name).get("compiler_kind", ""))
            == "finetune_lora"
        )

    @objc.python_method
    def _job_matches_current_behavior(
        self, job: dict[str, Any]
    ) -> bool:
        behavior = str(job.get("behavior_hash", ""))
        if behavior:
            return behavior == self._current_behavior_hash
        return str(job.get("source_hash", "")) == self._current_source_hash

    @objc.python_method
    def _draft_candidate_job(self) -> dict[str, Any]:
        job = dict(self._finetune_status.get("job") or {})
        if (
            str(job.get("compiler", "")) == self.resolved_draft_compiler()
            and self._job_matches_current_behavior(job)
        ):
            return job
        return {}

    @objc.python_method
    def _draft_program_id(self) -> str:
        compiler = self.resolved_draft_compiler()
        if (
            self._current_behavior_hash == self._active_behavior_hash
            and compiler == self.resolved_active_compiler()
        ):
            return self.active_program_id
        artifact = self._artifact_for_compiler(compiler)
        if artifact:
            return str(artifact.get("program_id", ""))
        job = self._draft_candidate_job()
        if str(job.get("status", "")) == "ready":
            return str(job.get("program_id", ""))
        return ""

    @objc.python_method
    def _set_draft_compiler(
        self, name: str, *, explicit: bool
    ) -> None:
        self._cancel_queue_for_draft_change(
            "Draft compiler changed after deployment was queued.")
        self._clear_diagnostics()
        self.draft_compiler = str(name)
        info = self.compiler_info(self.draft_compiler)
        artifact = self._artifact_for_compiler(self.draft_compiler)
        self.draft_compiler_snapshot = str(
            artifact.get("compiler_snapshot")
            or info.get("latest_snapshot", ""))
        self._draft_compiler_explicit = explicit
        if explicit:
            self.compiler_mode = revisions.EXPLICIT_COMPILER_MODE
        self._compiler_dirty = self._compiler_selection_dirty()
        self._validation_target = {
            "compiler": self.resolved_draft_compiler(),
            "compiler_snapshot": self.draft_compiler_snapshot,
            "program_id": self._draft_program_id(),
        }
        self._reconcile_validation_results()
        self._refresh_validation_result_labels()
        self._dirty = (
            self._source_dirty
            or self._coverage_dirty
            or self._compiler_dirty
            or self._validation_dirty
        )
        self.window.setDocumentEdited_(self._dirty)
        self._refresh_ui()

    @objc.python_method
    def _set_compiler_mode(self, mode: str) -> None:
        if mode not in revisions.COMPILER_MODES:
            return
        self._cancel_queue_for_draft_change(
            "Draft compiler mode changed after deployment was queued.")
        self._clear_diagnostics()
        self.compiler_mode = mode
        self._draft_compiler_explicit = (
            mode == revisions.EXPLICIT_COMPILER_MODE)
        if mode == revisions.AUTOMATIC_COMPILER_MODE:
            info = self.automatic_base_compiler_info()
            self.draft_compiler = str(info.get("name", ""))
            self.draft_compiler_snapshot = str(
                info.get("latest_snapshot", ""))
        self._compiler_dirty = self._compiler_selection_dirty()
        self._validation_target = {
            "compiler": self.resolved_draft_compiler(),
            "compiler_snapshot": self.draft_compiler_snapshot,
            "program_id": self._draft_program_id(),
        }
        self._reconcile_validation_results()
        self._refresh_validation_result_labels()
        self._dirty = (
            self._source_dirty
            or self._coverage_dirty
            or self._compiler_dirty
            or self._validation_dirty
        )
        self.window.setDocumentEdited_(self._dirty)
        self._refresh_ui()

    @objc.python_method
    def _sync_draft_compiler_for_source(self) -> None:
        draft_source_changed = bool(
            not self._active_hash
            or self._current_behavior_hash != self._active_behavior_hash
        )
        if self.compiler_mode == revisions.AUTOMATIC_COMPILER_MODE:
            automatic = self.automatic_base_compiler_info()
            self.draft_compiler = str(automatic.get("name", ""))
            self._draft_compiler_explicit = False
        elif not self.draft_compiler:
            self.draft_compiler = str(
                self.compiler_info().get("name", ""))
        if (
            self.compiler_mode == revisions.EXPLICIT_COMPILER_MODE
            and not draft_source_changed
            and not self._draft_compiler_explicit
        ):
            self.draft_compiler = self.resolved_active_compiler()
        if (
            self.compiler_mode == revisions.EXPLICIT_COMPILER_MODE
            and draft_source_changed
            and not self._draft_compiler_explicit
            and self.compiler_requires_build(
                self.resolved_draft_compiler())
        ):
            self.draft_compiler = str(
                self.compiler_info().get("name", ""))
        info = self.compiler_info(self.resolved_draft_compiler())
        artifact = (
            self._artifact_for_compiler(self.resolved_draft_compiler())
            if self.compiler_mode == revisions.EXPLICIT_COMPILER_MODE
            else {}
        )
        self.draft_compiler_snapshot = str(
            artifact.get("compiler_snapshot")
            or info.get("latest_snapshot", ""))
        self._compiler_dirty = self._compiler_selection_dirty()

    @objc.python_method
    def compiler_sheet_items(
        self, active: dict[str, Any]
    ) -> list[dict[str, Any]]:
        deployed = bool(active.get("source_hash") or self._active_hash)
        if isinstance(active.get("artifacts"), dict):
            self.active_artifacts = dict(active.get("artifacts") or {})
        default_info = self.compiler_info()
        active_name = str(
            active.get("compiler")
            or self.active_compiler
            or default_info.get("name", "")
        )
        items = [dict(item) for item in self.compiler_catalog]
        if active_name and not any(
            str(item.get("name", "")) == active_name for item in items
        ):
            items.append(self.compiler_info(active_name))

        rows = []
        draft_name = self.resolved_draft_compiler()
        source_matches_active = (
            bool(self._active_hash)
            and self._current_behavior_hash == self._active_behavior_hash
        )
        candidate_job = dict(self._finetune_status.get("job") or {})
        for item in items:
            name = str(item.get("name", ""))
            raw_description = str(
                item.get("description") or name or "Unnamed compiler")
            label, separator, detail = raw_description.partition("—")
            is_active = bool(deployed and name == active_name)
            is_draft = bool(
                self.compiler_mode == revisions.EXPLICIT_COMPILER_MODE
                and name == draft_name)
            requires_build = (
                str(item.get("compiler_kind", "")) == "finetune_lora")
            job_matches = (
                str(candidate_job.get("compiler", "")) == name
                and self._job_matches_current_behavior(candidate_job)
            )
            job_status = (
                str(candidate_job.get("status", ""))
                if job_matches else "")
            artifact = (
                self._artifact_for_compiler(name)
                if source_matches_active else {})
            ready = bool(
                not requires_build
                or (is_active and source_matches_active)
                or artifact
                or job_status == "ready"
            )
            if requires_build and job_status == "building":
                action = "cancel"
                action_title = "Cancel"
            elif requires_build and not ready:
                action = "build"
                action_title = "Build…"
            elif not is_draft:
                action = "select"
                action_title = "Use"
            else:
                action = ""
                action_title = ""
            if (
                not requires_build
                and bool(item.get("default"))
                and str(candidate_job.get("status", "")) == "building"
                and self._job_matches_current_behavior(candidate_job)
                and self.compiler_requires_build(draft_name)
            ):
                action = "deploy_now"
                action_title = "Use & Deploy…"
            rows.append({
                **item,
                "name": name,
                "label": label.strip() or name,
                "detail": detail.strip() if separator else raw_description,
                "is_active": is_active,
                "is_draft": is_draft,
                "is_paw_default": bool(item.get("default")),
                "requires_build": requires_build,
                "ready_for_draft": ready,
                "job_status": job_status,
                "action": action,
                "action_title": action_title,
                "can_build": bool(
                    name
                    and item.get("supports_local_sdk")
                    and action in (
                        "build", "select", "cancel", "deploy_now")
                ),
            })
        default_runtime = str(default_info.get("runtime_id", ""))
        rows.sort(key=lambda item: (
            0 if item["is_active"] else 1,
            0
            if default_runtime
            and str(item.get("runtime_id", "")) == default_runtime
            else 1,
            0
            if item["is_paw_default"]
            else (
                1
                if item.get("compiler_kind") == "finetune_lora"
                else 2
            ),
        ))
        automatic_selected = (
            self.compiler_mode == revisions.AUTOMATIC_COMPILER_MODE)
        automatic_active = bool(
            deployed
            and str(
                active.get("compiler_mode")
                or self.active_compiler_mode
                or revisions.AUTOMATIC_COMPILER_MODE
            ) == revisions.AUTOMATIC_COMPILER_MODE
        )
        automatic = {
            "name": "__automatic__",
            "label": "Automatic",
            "description": (
                "Automatic — deploy quickly, then optimize the deployed "
                "revision in the background"
            ),
            "detail": (
                "Uses a fast compatible compiler for Deploy and Run Tests, "
                "then automatically switches to a compatible finetuned build."
            ),
            "latest_snapshot": "managed dynamically",
            "is_active": automatic_active,
            "is_draft": automatic_selected,
            "is_paw_default": False,
            "requires_build": False,
            "ready_for_draft": True,
            "job_status": "",
            "action": "" if automatic_selected else "automatic",
            "action_title": "" if automatic_selected else "Use",
            "can_build": not automatic_selected,
            "supports_local_sdk": True,
        }
        return [automatic, *rows]

    @objc.python_method
    def compiler_catalog_accessory(
        self,
        alert,
        active: dict[str, Any],
        pending: dict[str, Any],
    ):
        rows = self.compiler_sheet_items(active)
        self._compiler_sheet_rows = rows
        width = 560
        row_height = 94
        document_height = max(row_height, len(rows) * row_height)
        visible_height = min(document_height, row_height * 3)
        accessory = RAPFlippedView.alloc().initWithFrame_(
            NSMakeRect(0, 0, width, 42 + visible_height))

        heading = self._label("Compilers from PAW", size=11, bold=True)
        heading.setFrame_(NSMakeRect(0, 0, 260, 18))
        accessory.addSubview_(heading)
        catalog_state = "Cached catalog" if self.compiler_catalog_cached else (
            "Current catalog")
        if self.compiler_catalog_offline:
            catalog_state += " · offline"
        source = self._label(
            catalog_state,
            size=9,
            color=NSColor.secondaryLabelColor(),
        )
        source.setFrame_(NSMakeRect(0, 20, 300, 16))
        accessory.addSubview_(source)

        def close_with(
            *,
            compiler: str = "",
            action: str = "",
            refresh: bool = False,
        ) -> None:
            pending["compiler"] = compiler
            pending["action"] = action
            pending["refresh"] = refresh
            alert.buttons()[0].performClick_(None)

        refresh = self._button(
            "Refresh",
            lambda _sender: close_with(refresh=True),
            role="flat",
            key_view=False,
        )
        refresh.setFrame_(NSMakeRect(width - 74, 1, 74, 24))
        accessory.addSubview_(refresh)

        scroll = NSScrollView.alloc().initWithFrame_(
            NSMakeRect(0, 42, width, visible_height))
        scroll.setHasVerticalScroller_(document_height > visible_height)
        scroll.setAutohidesScrollers_(True)
        scroll.setDrawsBackground_(False)
        document = RAPFlippedView.alloc().initWithFrame_(
            NSMakeRect(0, 0, width - 16, document_height))
        scroll.setDocumentView_(document)
        accessory.addSubview_(scroll)

        for index, item in enumerate(rows):
            y = index * row_height
            title = self._label(
                str(item.get("label") or item.get("name")),
                size=12,
                bold=True,
            )
            title.setFrame_(NSMakeRect(12, y + 8, 350, 19))
            document.addSubview_(title)

            badges = []
            if item.get("is_active"):
                badges.append("Deployed")
            if item.get("is_draft"):
                badges.append("✓ Draft")
                if (
                    item.get("requires_build")
                    and not item.get("ready_for_draft")
                ):
                    badges.append("build required")
            if item.get("job_status") == "ready":
                badges.append("Ready")
            elif item.get("job_status") == "building":
                badges.append("Building")
            if item.get("is_paw_default"):
                badges.append("PAW default")
            if not item.get("supports_local_sdk", False):
                badges.append("Unavailable locally")
            if badges:
                badge = self._label(
                    " · ".join(badges),
                    size=9.5,
                    bold=bool(
                        item.get("is_active") or item.get("is_draft")),
                    color=(
                        NSColor.systemBlueColor()
                        if item.get("is_draft")
                        else (
                            NSColor.systemGreenColor()
                            if item.get("is_active")
                            else NSColor.secondaryLabelColor()
                        )
                    ),
                )
                badge.setFrame_(NSMakeRect(366, y + 9, 180, 18))
                document.addSubview_(badge)

            detail = self._label(
                str(item.get("detail", "")),
                size=10,
                color=NSColor.secondaryLabelColor(),
                lines=2,
            )
            detail.setPreferredMaxLayoutWidth_(430)
            detail.setFrame_(NSMakeRect(12, y + 31, 430, 34))
            document.addSubview_(detail)

            technical = self._label(
                (
                    "Managed from the current PAW compiler catalog"
                    if item.get("name") == "__automatic__"
                    else (
                        f"{item.get('name') or 'unknown'} · "
                        f"{item.get('latest_snapshot') or 'snapshot unavailable'}"
                    )
                ),
                size=8.5,
                color=NSColor.tertiaryLabelColor(),
            )
            fixed_font = NSFont.userFixedPitchFontOfSize_(8.5)
            if fixed_font is not None:
                technical.setFont_(fixed_font)
            technical.setLineBreakMode_(NSLineBreakByTruncatingTail)
            technical.setFrame_(NSMakeRect(12, y + 68, 430, 15))
            document.addSubview_(technical)

            if item.get("action"):
                build = self._button(
                    str(item.get("action_title", "")),
                    lambda _sender,
                    name=str(item.get("name", "")),
                    action=str(item.get("action", "")): (
                        close_with(compiler=name, action=action)
                    ),
                    role="secondary",
                    key_view=False,
                )
                build.setFrame_(NSMakeRect(466, y + 35, 78, 28))
                build.setEnabled_(bool(item.get("can_build")))
                document.addSubview_(build)

            if index < len(rows) - 1:
                separator = NSBox.alloc().initWithFrame_(
                    NSMakeRect(12, y + row_height - 1, width - 40, 1))
                separator.setBoxType_(NSBoxSeparator)
                document.addSubview_(separator)

        return accessory

    @objc.python_method
    def reload_validation_cases(self) -> None:
        request = {
            "type": "rule_get",
            "rule_id": self.rule_id,
            "project_root": self.project_root,
        }

        def completed(result):
            def apply():
                if not result.get("ok"):
                    return
                info = result.get("rule") or {}
                self.validation_cases = list(
                    info.get("validation_cases") or [])
                self._saved_validation_cases = json.dumps(
                    self.validation_cases, sort_keys=True)
                self._validation_dirty = False
                self._dirty = self._source_dirty or self._coverage_dirty
                self._render_validation_cases()
                self._refresh_ui()
                self._schedule_content_fit()
            _on_main(apply)

        if hasattr(self.model, "query"):
            self.model.query(request, completed)
        else:
            self.model.perform(request, completed)

    @objc.python_method
    def show_compilation(self) -> None:
        if not self.compiler_catalog and not self._compiler_catalog_attempted:
            self.reload_compiler_catalog(then=self.show_compilation)
            return
        def completed(result):
            _on_main(lambda: self._show_compilation_result(result))

        request = {
            "type": "finetune_status",
            "rule_id": self.rule_id,
            "project_root": self.project_root,
        }
        if hasattr(self.model, "query"):
            self.model.query(request, completed)
        else:
            self.model.perform(request, completed)

    @objc.python_method
    def _show_compilation_result(self, result: dict[str, Any]) -> None:
        if not result.get("ok"):
            self._set_compilation_message(
                result.get("error", "Compilation status is unavailable."))
            return
        self._apply_finetune_status(result)
        active = result.get("active") or {}
        active_label = self.compiler_label(str(active.get("compiler", "")))
        alert = NSAlert.alloc().init()
        alert.setMessageText_("Draft compiler")
        alert.setInformativeText_(
            (
                (
                    f"Automatic is active with {active_label}. Deploy uses a "
                    "fast compiler, then optimizes in the background. Choose "
                    "a specific compiler to pin it instead."
                )
                if self.compiler_mode == revisions.AUTOMATIC_COMPILER_MODE
                else (
                    f"{active_label} is deployed. Choose or build the compiler "
                    "for the current editor draft; Deploy is the only action "
                    "that changes the running rule."
                )
            )
            if self._active_hash
            else (
                "Choose or build the compiler for this draft. Nothing runs "
                "until you Deploy."
            )
        )
        catalog_action = {
            "compiler": "", "action": "", "refresh": False}
        alert.addButtonWithTitle_("Close")
        alert.setAccessoryView_(
            self.compiler_catalog_accessory(
                alert, active, catalog_action))

        def finished(_response):
            compiler = str(catalog_action.get("compiler", ""))
            action = str(catalog_action.get("action", ""))
            if action == "automatic":
                self._set_compiler_mode(revisions.AUTOMATIC_COMPILER_MODE)
            elif action == "select" and compiler:
                self._set_draft_compiler(compiler, explicit=True)
            elif action == "deploy_now" and compiler:
                self._set_draft_compiler(compiler, explicit=True)
                self.deploy()
            elif action == "build" and compiler:
                self._set_draft_compiler(compiler, explicit=True)
                self._selected_build_compiler = compiler
                self._perform_finetune_action("start_finetune")
            elif action == "cancel":
                self._perform_finetune_action("cancel_finetune")
            elif catalog_action.get("refresh"):
                self._compiler_catalog_attempted = False
                self.reload_compiler_catalog(
                    refresh=True, then=self.show_compilation)

        alert.beginSheetModalForWindow_completionHandler_(
            self.window, finished)

    @objc.python_method
    def _perform_finetune_action(self, action: str) -> None:
        request = {
            "type": action,
            "rule_id": self.rule_id,
            "project_root": self.project_root,
        }
        if action == "start_finetune":
            self._clear_diagnostics()
            request["compiler"] = str(
                getattr(self, "_selected_build_compiler", ""))
            self._capture()
            self._capture_validation_cases()
            ok, source, error = self._compose()
            if not ok:
                self._set_compilation_message(error)
                return
            self._current_source_hash = revisions.hash_source(source)
            request["source"] = source
            request["validation_cases"] = list(self.validation_cases)

        def completed(result):
            def apply():
                if not result.get("ok"):
                    self._set_compilation_message(
                        result.get("error", "Compilation action failed."))
                    return
                if action == "start_finetune":
                    self._finetune_status = {
                        "job": result.get("job") or {"status": "building"},
                    }
                    self._clear_diagnostics()
                    self._schedule_finetune_poll()
                else:
                    self._finetune_status = {}
                self._refresh_ui()
            _on_main(apply)

        self.model.perform(request, completed, timeout=10)

    @objc.python_method
    def _set_compilation_message(
        self, message: str, operation_id: str = ""
    ) -> None:
        self._diagnostic_operation_id = operation_id
        self.diagnostics_label.setStringValue_(message)
        self.diagnostics_label.setTextColor_(NSColor.systemRedColor())
        self.diagnostics_label.setHidden_(False)

    @objc.python_method
    def _clear_diagnostics(self, operation_id: str = "") -> None:
        if (
            operation_id
            and self._diagnostic_operation_id
            and operation_id != self._diagnostic_operation_id
        ):
            return
        self._diagnostic_operation_id = ""
        self.diagnostics_label.setStringValue_("")
        self.diagnostics_label.setHidden_(True)
        self.rule["_deploy_failed"] = False

    @objc.python_method
    def _apply_finetune_status(self, result: dict[str, Any]) -> None:
        self._finetune_status = dict(result)
        active = result.get("active") or {}
        self.active_compiler = str(active.get("compiler", ""))
        self.active_compiler_snapshot = str(
            active.get("compiler_snapshot", ""))
        self.active_program_id = str(active.get("program_id", ""))
        self.active_compiler_mode = str(
            active.get("compiler_mode")
            or self.active_compiler_mode
            or revisions.AUTOMATIC_COMPILER_MODE)
        self.active_artifacts = dict(
            active.get("artifacts") or self.active_artifacts)
        if not self._compiler_dirty:
            self.compiler_mode = self.active_compiler_mode
            self._sync_draft_compiler_for_source()
        job = result.get("job") or {}
        job_status = str(job.get("status", ""))
        job_id = str(job.get("id", ""))
        if job_status in ("building", "ready", "activated", "deployed"):
            self._clear_diagnostics()
        elif job_status == "failed":
            self._set_compilation_message(
                str(job.get("error") or "Compiler build failed."),
                job_id,
            )
        self._refresh_ui()
        if job_status in ("waiting_for_build", "building"):
            self._schedule_finetune_poll()
        elif job_status == "ready" and not job.get("automatic"):
            self.reload_validation_results()

    @objc.python_method
    def _schedule_finetune_poll(self) -> None:
        if self._finetune_poll_timer:
            self._finetune_poll_timer.cancel()

        def poll():
            request = {
                "type": "finetune_status",
                "rule_id": self.rule_id,
                "project_root": self.project_root,
            }

            def completed(result):
                if result.get("ok"):
                    _on_main(lambda: self._apply_finetune_status(result))

            if hasattr(self.model, "query"):
                self.model.query(request, completed)
            else:
                self.model.perform(request, completed)

        timer = threading.Timer(5.0, poll)
        timer.daemon = True
        self._finetune_poll_timer = timer
        timer.start()

    @objc.python_method
    def show_compiled_spec(self) -> None:
        self._capture()
        mask = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskResizable
        )
        window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, 700, 520), mask,
            NSBackingStoreBuffered, False)
        window.setTitle_("Compiled PAW Specification")
        scroll = NSScrollView.alloc().initWithFrame_(
            window.contentView().bounds())
        scroll.setHasVerticalScroller_(True)
        scroll.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)
        editor = NSTextView.alloc().initWithFrame_(scroll.bounds())
        editor.setEditable_(False)
        editor.setSelectable_(True)
        editor.setFont_(NSFont.monospacedSystemFontOfSize_weight_(11, 0))
        editor.setString_(self.spec)
        scroll.setDocumentView_(editor)
        window.contentView().addSubview_(scroll)
        window.center()
        window.makeKeyAndOrderFront_(None)
        self._compiled_spec_window = window
        self._compiled_spec_editor = editor

    @objc.python_method
    def show_advanced(self) -> None:
        if self._advanced_window:
            self._advanced_window.makeKeyAndOrderFront_(None)
            return
        ok, composed, error = self._compose()
        if ok:
            self.full_source = composed
        else:
            self.diagnostics_label.setStringValue_(error)
            self.diagnostics_label.setHidden_(False)
            return
        mask = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskResizable
        )
        window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, 900, 680), mask,
            NSBackingStoreBuffered, False)
        window.setTitle_(f"Underlying Python — {self.name}")
        window.setDelegate_(self)
        window.setContentMinSize_(NSMakeSize(680, 520))
        root = window.contentView()
        heading = self._label(
            f"{len(self.cases)} test case(s) · {len(self.probes)} command probe(s)",
            size=10, color=NSColor.secondaryLabelColor())
        heading.setFrame_(NSMakeRect(18, 642, 520, 20))
        heading.setAutoresizingMask_(
            NSViewWidthSizable | NSViewMinYMargin)
        root.addSubview_(heading)
        scroll = NSScrollView.alloc().initWithFrame_(
            NSMakeRect(18, 58, 864, 574))
        scroll.setAutoresizingMask_(
            NSViewWidthSizable | NSViewHeightSizable)
        scroll.setHasVerticalScroller_(True)
        scroll.setHasHorizontalScroller_(True)
        editor = NSTextView.alloc().initWithFrame_(
            NSMakeRect(0, 0, 848, 574))
        editor.setRichText_(False)
        editor.setAllowsUndo_(True)
        editor.setFont_(NSFont.userFixedPitchFontOfSize_(11.5))
        editor.setAutoresizingMask_(
            NSViewWidthSizable | NSViewHeightSizable)
        editor.setString_(self.full_source)
        scroll.setDocumentView_(editor)
        root.addSubview_(scroll)
        apply = self._button(
            "Apply Python", lambda _sender: self.apply_advanced(),
            role="primary", key_view=False)
        apply.setEnabled_(not self._busy)
        apply.setFrame_(NSMakeRect(750, 16, 132, 30))
        apply.setAutoresizingMask_(NSViewMinXMargin)
        root.addSubview_(apply)
        copy_id = self._button(
            "Copy Rule ID", lambda _sender: self.copy_rule_id(), role="flat",
            key_view=False)
        copy_id.setFrame_(NSMakeRect(18, 16, 100, 30))
        root.addSubview_(copy_id)
        open_file = self._button(
            "Open File", lambda _sender: self.open_external(), role="flat",
            key_view=False)
        open_file.setFrame_(NSMakeRect(126, 16, 88, 30))
        root.addSubview_(open_file)
        self._advanced_window = window
        self._advanced_editor = editor
        self._advanced_apply = apply
        self._refresh_finding_context()
        window.center()
        window.makeKeyAndOrderFront_(None)

    @objc.python_method
    def apply_advanced(self) -> None:
        if self._busy:
            return
        source = str(self._advanced_editor.string())
        projection = rules_api.source_projection(source)
        self.full_source = source
        if projection.get("ok"):
            self._apply_projection(projection)
        else:
            self.custom = True
        self._source_dirty = True
        self._current_source_hash = revisions.hash_source(source)
        self._current_behavior_hash = revisions.behavior_hash(source)
        self._sync_draft_compiler_for_source()
        self._dirty = True
        self._invalidate_validation_results()
        self.window.setDocumentEdited_(True)
        self._advanced_window.close()
        self._advanced_window = None
        self._advanced_editor = None
        self._advanced_apply = None
        self._refresh_ui(sync_text=not self.custom)

    @objc.python_method
    def _set_busy(
        self, busy: bool, status: str = "", *, busy_label: str = ""
    ) -> None:
        self._busy = busy
        self._busy_label = busy_label if busy else ""
        for control in self._interactive_controls:
            if isinstance(control, (NSTextField, NSTextView)):
                if hasattr(control, "setEditable_"):
                    control.setEditable_(not busy)
                if hasattr(control, "setSelectable_"):
                    control.setSelectable_(True)
            elif hasattr(control, "setEnabled_"):
                control.setEnabled_(not busy)
        for input_field, output in getattr(
            self, "validation_controls", []
        ):
            input_field.setEditable_(not busy)
            input_field.setSelectable_(True)
            output.setEnabled_(not busy)
        if hasattr(self.description_editor, "setEditable_"):
            self.description_editor.setEditable_(not busy and not self.custom)
        if self._advanced_editor:
            self._advanced_editor.setEditable_(not busy)
        if self._advanced_apply:
            self._advanced_apply.setEnabled_(not busy)
        if status:
            self.diagnostics_label.setStringValue_(status)
            self.diagnostics_label.setTextColor_(
                NSColor.secondaryLabelColor())
            self.diagnostics_label.setHidden_(False)
        self._refresh_ui()

    @objc.python_method
    def deploy(self) -> None:
        if self._busy:
            return
        if not self._validate_form_before_deploy():
            return
        draft_compiler = self.resolved_draft_compiler()
        if not self._active_hash and not self._scope_confirmed:
            self.show_projects_sheet(on_confirm=self.deploy)
            return
        self._capture()
        level_check = rules_api.inspect_spec_levels(self.spec)
        warning_hash = revisions.hash_source(self.spec)
        if (
            not level_check["ok"]
            and self._confirmed_spec_warning_hash != warning_hash
        ):
            self.confirm_spec_warning(level_check["warning"], warning_hash)
            return
        ok, source, error = self._compose()
        if not ok:
            self._deployment_failed(error)
            return
        source_hash = revisions.hash_source(source)
        source_changed = source_hash != self._active_hash
        build_job = self._finetune_status.get("job") or {}
        if (
            self.compiler_requires_build(draft_compiler)
            and not self._draft_program_id()
        ):
            if (
                str(build_job.get("status", "")) == "building"
                and self._job_matches_current_behavior(build_job)
                and str(build_job.get("compiler", "")) == draft_compiler
            ):
                self._queue_current_deployment(
                    source, source_hash, level_check)
            else:
                self._set_compilation_message(
                    f"Build {self.compiler_label(draft_compiler)} for this "
                    "draft before deploying.")
            return
        stale_build_running = bool(
            str(build_job.get("status", "")) == "building"
            and not self._job_matches_current_behavior(build_job)
        )
        if (
            source_changed
            and stale_build_running
            and self._confirmed_build_discard_hash != source_hash
        ):
            self.confirm_deploy_during_compiler_build(source_hash)
            return
        self._queue_current_deployment(
            source, source_hash, level_check)
        return

    @objc.python_method
    def _validate_form_before_deploy(self) -> bool:
        self._capture()
        if not self.custom and self.trigger not in TRIGGERS:
            self.trigger_error_label.setHidden_(False)
            self.metadata_stack.scrollRectToVisible_(
                self.metadata_stack.bounds())
            self.window.makeFirstResponder_(self.trigger_popup)
            return False
        self.trigger_error_label.setHidden_(True)
        if not self.name.strip():
            self.window.makeFirstResponder_(self.name_field)
            self._set_compilation_message("Enter a rule name.")
            return False
        if not self.custom and not self.spec.strip():
            self.window.makeFirstResponder_(self.description_editor)
            self._set_compilation_message("Enter a PAW specification.")
            return False
        return True

    @objc.python_method
    def _queue_current_deployment(
        self,
        source: str,
        source_hash: str,
        level_check: dict[str, Any],
    ) -> None:
        self._capture_validation_cases()
        self.rule["_deploy_failed"] = False
        self._clear_diagnostics()
        if not self._pending_deployment_id:
            self._pending_deployment_id = secrets.token_urlsafe(18)
        deployment_id = self._pending_deployment_id
        queued_generation = self._draft_generation
        queued_compiler = self.resolved_draft_compiler()
        queued_compiler_mode = self.compiler_mode
        queued_compiler_snapshot = self.draft_compiler_snapshot
        queued_cases = json.dumps(
            self.validation_cases, sort_keys=True, ensure_ascii=False)
        queued_coverage = json.dumps({
            "mode": self.coverage_mode,
            "selected_projects": sorted(self.selected_projects),
        }, sort_keys=True)
        self.diagnostics_label.setStringValue_(
            "Queuing this exact draft for background deployment…")
        self.diagnostics_label.setTextColor_(
            NSColor.secondaryLabelColor())
        self.diagnostics_label.setHidden_(False)

        request = {
            "type": "queue_deployment",
            "deployment_id": deployment_id,
            "rule_id": self.rule_id,
            "project_root": self.project_root,
            "source": source,
            "source_hash": source_hash,
            "expected_active_hash": self._active_hash,
            "compiler": queued_compiler,
            "compiler_mode": self.compiler_mode,
            "compiler_snapshot": queued_compiler_snapshot,
            "program_id": self._draft_program_id(),
            "coverage": {
                "mode": self.coverage_mode,
                "selected_projects": self.selected_projects,
            },
            "warnings": (
                [level_check["warning"]] if not level_check["ok"] else []),
            "validation_cases": self.validation_cases,
        }

        def apply_result(result):
            if not result.get("ok"):
                self._set_compilation_message(
                    result.get(
                        "error", "Deployment could not be queued."))
                return
            current_cases = json.dumps(
                self.validation_cases,
                sort_keys=True,
                ensure_ascii=False,
            )
            current_coverage = json.dumps({
                "mode": self.coverage_mode,
                "selected_projects": sorted(self.selected_projects),
            }, sort_keys=True)
            if (
                self._draft_generation != queued_generation
                or self._current_source_hash != source_hash
                or self.resolved_draft_compiler() != queued_compiler
                or self.compiler_mode != queued_compiler_mode
                or self.draft_compiler_snapshot
                != queued_compiler_snapshot
                or current_cases != queued_cases
                or current_coverage != queued_coverage
            ):
                self._deployment_queue = dict(
                    result.get("queue") or {})
                self.cancel_queued_deployment(
                    "Draft changed while deployment was being queued.")
                return
            self._apply_deployment_queue(
                dict(result.get("queue") or {}))
            self.diagnostics_label.setStringValue_(
                "Deployment queued for this exact draft.")
            self.diagnostics_label.setTextColor_(
                NSColor.systemBlueColor())
            self.diagnostics_label.setHidden_(False)
            self._close_queued_editor()

        def completed(result):
            error = str(result.get("error", ""))
            if not result.get("ok") and (
                "did not respond" in error.lower()
                or "timed out" in error.lower()
            ):
                self._recover_deployment_after_disconnect(
                    request, deployment_id, queued_generation, apply_result)
                return
            _on_main(lambda: apply_result(result))

        self.model.perform(request, completed, timeout=10)

    @objc.python_method
    def _close_queued_editor(self) -> None:
        if self._queue_is_pending() and self.window.isVisible():
            self.window.close()

    @objc.python_method
    def _recover_deployment_after_disconnect(
        self,
        request: dict[str, Any],
        deployment_id: str,
        queued_generation: int,
        apply_result: Callable[[dict[str, Any]], None],
    ) -> None:
        self.diagnostics_label.setStringValue_(
            "Connection lost — checking deployment status…")
        self.diagnostics_label.setTextColor_(
            NSColor.systemOrangeColor())
        self.diagnostics_label.setHidden_(False)

        def recover():
            if not ipc.ensure_daemon(wait=8.0):
                result = {
                    "ok": False,
                    "error": (
                        "Could not reconnect to the daemon. "
                        "The draft is unchanged; click Deploy to retry."
                    ),
                }
            else:
                status = ipc.send_request({
                    "type": "deployment_queue_status",
                    "rule_id": self.rule_id,
                    "deployment_id": deployment_id,
                }, timeout=10)
                if status and status.get("ok") and status.get("queue"):
                    result = status
                elif self._draft_generation == queued_generation:
                    result = ipc.send_request(
                        request, timeout=15) or {
                            "ok": False,
                            "error": (
                                "The daemon reconnected but deployment could "
                                "not be queued. Click Deploy to retry."
                            ),
                        }
                else:
                    result = {
                        "ok": False,
                        "error": (
                            "Deployment was not retried because the draft "
                            "changed during reconnection."
                        ),
                    }
            _on_main(lambda: apply_result(result))

        worker = threading.Thread(
            target=recover,
            name="rap-deployment-recovery",
            daemon=True,
        )
        self._deployment_recovery_thread = worker
        worker.start()

    @objc.python_method
    def confirm_spec_warning(self, warning: str, warning_hash: str) -> None:
        alert = NSAlert.alloc().init()
        alert.setMessageText_("PAW output levels may be unclear")
        alert.setInformativeText_(
            warning + "\n\nThe specification will be compiled exactly as "
            "written. RAP will not add or rewrite anything.")
        alert.addButtonWithTitle_("Edit Specification")
        alert.addButtonWithTitle_("Deploy Anyway")

        def completed(response):
            if response == NSAlertSecondButtonReturn:
                self._confirmed_spec_warning_hash = warning_hash
                self.deploy()
            else:
                self.window.makeFirstResponder_(self.description_editor)

        alert.beginSheetModalForWindow_completionHandler_(
            self.window, completed)

    @objc.python_method
    def confirm_deploy_during_compiler_build(
        self, source_hash: str
    ) -> None:
        alert = NSAlert.alloc().init()
        alert.setMessageText_("Deploy changes while a compiler is building?")
        alert.setInformativeText_(
            "The running build belongs to the currently deployed revision. "
            "Deploying these changes will discard that build; you can start "
            "a new one for the new revision afterward.")
        alert.addButtonWithTitle_("Keep Editing")
        alert.addButtonWithTitle_("Deploy and Discard Build")

        def completed(response):
            if response == NSAlertSecondButtonReturn:
                self._confirmed_build_discard_hash = source_hash
                self.deploy()

        alert.beginSheetModalForWindow_completionHandler_(
            self.window, completed)

    @objc.python_method
    def _deployment_failed(self, error: str) -> None:
        self.rule["_deploy_failed"] = True
        self.diagnostics_label.setStringValue_(
            f"Deploy failed. The previous deployment is still active.\n{error}")
        self.diagnostics_label.setTextColor_(NSColor.systemRedColor())
        self.diagnostics_label.setHidden_(False)
        self._set_busy(False)

    @objc.python_method
    def save_draft(self) -> None:
        if self._busy:
            return
        if self._queue_is_pending():
            self.diagnostics_label.setStringValue_(
                "This exact draft is already persisted in the deployment queue.")
            self.diagnostics_label.setTextColor_(
                NSColor.secondaryLabelColor())
            self.diagnostics_label.setHidden_(False)
            return
        ok, source, error = self._compose()
        if not ok:
            self._deployment_failed(error)
            return
        self._set_busy(
            True, "Saving local draft…", busy_label="Saving draft")
        definition = self.rule.get("definition") or {}
        if self.rule.get("scope") == "project":
            request = {
                "type": "save_project_draft",
                "rule_id": self.rule_id,
                "source": source,
                "project_root": (
                    definition.get("project_root") or self.project_root),
                "expected_source_hash": definition.get("source_hash", ""),
                "coverage": {
                    "mode": self.coverage_mode,
                    "selected_projects": self.selected_projects,
                    "confirmed": self._scope_confirmed,
                    "compiler": self.resolved_draft_compiler(),
                    "compiler_mode": self.compiler_mode,
                    "compiler_snapshot": self.draft_compiler_snapshot,
                },
                "validation_cases": self.validation_cases,
            }
        else:
            request = {
                "type": "save_library_draft",
                "rule_id": self.rule_id,
                "source": source,
                "expected_source_hash": definition.get("source_hash", ""),
                "expected_absent": not bool(definition),
                "coverage": {
                    "mode": self.coverage_mode,
                    "selected_projects": self.selected_projects,
                    "confirmed": self._scope_confirmed,
                    "compiler": self.resolved_draft_compiler(),
                    "compiler_mode": self.compiler_mode,
                    "compiler_snapshot": self.draft_compiler_snapshot,
                },
                "validation_cases": self.validation_cases,
            }

        def complete(result: dict[str, Any]) -> None:
            def apply() -> None:
                if not result.get("ok"):
                    self._close_after_save = False
                    self._deployment_failed(
                        result.get("error", "Draft could not be saved."))
                    return
                self.rule.update(result)
                self.rule["new_draft"] = not bool(self._active_hash)
                self.full_source = str(result.get("source", source))
                self._definition_hash = str(
                    (result.get("definition") or {}).get("source_hash", ""))
                self._working_hash = str(result.get("working_hash", ""))
                self._saved_source_hash = revisions.hash_source(self.full_source)
                self._source_dirty = False
                self.validation_cases = list(
                    result.get("validation_cases") or self.validation_cases)
                self._saved_validation_cases = json.dumps(
                    self.validation_cases, sort_keys=True)
                self._validation_dirty = False
                self._dirty = (
                    self._coverage_dirty or self._compiler_dirty)
                self.window.setDocumentEdited_(self._dirty)
                self.diagnostics_label.setStringValue_(
                    "Draft saved. Deploy when ready.")
                self._set_busy(False)
                if self.manager:
                    self.manager.changed(result)
                if self._close_after_save:
                    self._close_after_save = False
                    self.window.close()
            _on_main(apply)

        self.model.perform(request, complete)

    @objc.python_method
    def show_rule_actions(self, sender) -> None:
        menu = NSMenu.alloc().initWithTitle_("Rule")
        lifecycle = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            self._lifecycle_title(), "invoke:", "")
        self._wire(
            lifecycle,
            lambda _sender: self.confirm_lifecycle_action(),
            key_view=False,
        )
        menu.addItem_(lifecycle)
        menu.addItem_(NSMenuItem.separatorItem())
        copy_id = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Copy Rule ID", "invoke:", "")
        self._wire(
            copy_id, lambda _sender: self.copy_rule_id(), key_view=False)
        menu.addItem_(copy_id)
        menu.popUpMenuPositioningItem_atLocation_inView_(
            None, (0, sender.bounds().size.height), sender)

    @objc.python_method
    def confirm_lifecycle_action(self) -> None:
        if self._busy:
            return
        if self.rule.get("new_draft") and not self.rule.get("path"):
            self._dirty = False
            self.window.close()
            return
        definition = self.rule.get("definition") or {}
        if not definition:
            self.diagnostics_label.setStringValue_(
                "Reload this rule before removing it.")
            return
        reverting = bool(
            self.rule.get("scope") == "project"
            and self.rule.get("customized_from"))
        state = self.manager.definition_state(definition)
        if state["busy"]:
            self.diagnostics_label.setStringValue_(
                "Wait for the open editor to finish deploying.")
            self.diagnostics_label.setHidden_(False)
            return
        self._lifecycle_confirmation_state = dict(state)
        title = (
            f"Use the library version of “{self.name}”?"
            if reverting else f"Delete “{self.name}”?")
        message = (
            "This removes the project customization and preserves project coverage."
            if reverting else
            "Open findings without a remaining rule move to Reviewed. "
            "Recorded source and audit history are kept."
        )
        if state["dirty"]:
            message += (
                f" {state['dirty']} open editor(s) have unsaved changes; "
                "those changes will be discarded."
            )
        alert = NSAlert.alloc().init()
        alert.setAlertStyle_(NSAlertStyleCritical)
        alert.setMessageText_(title)
        alert.setInformativeText_(message)
        alert.addButtonWithTitle_(
            "Use Library Version" if reverting else "Delete Rule")
        alert.addButtonWithTitle_("Cancel")

        def completed(response):
            if response == NSAlertFirstButtonReturn:
                self._perform_lifecycle_action(reverting)
            else:
                self._lifecycle_confirmation_state = None

        alert.beginSheetModalForWindow_completionHandler_(
            self.window, completed)

    @objc.python_method
    def _perform_lifecycle_action(self, reverting: bool) -> None:
        definition = dict(self.rule.get("definition") or {})
        if (
            self._lifecycle_confirmation_state is not None
            and self.manager.definition_state(definition)
            != self._lifecycle_confirmation_state
        ):
            self._lifecycle_confirmation_state = None
            self.diagnostics_label.setStringValue_(
                "Open editors changed after confirmation. Review and try again.")
            self.diagnostics_label.setHidden_(False)
            return
        self._lifecycle_confirmation_state = None
        self.manager.set_definition_pending(definition, True)
        request = {
            "type": "revert_to_shared" if reverting else "delete_rule",
            "rule_id": self.rule_id,
            "definition": definition,
        }
        if reverting:
            request["project_root"] = (
                definition.get("project_root") or self.project_root)

        def complete(result: dict[str, Any]) -> None:
            def apply() -> None:
                if not result.get("ok"):
                    self.manager.set_definition_pending(definition, False)
                    self.diagnostics_label.setStringValue_(
                        result.get("error", "Rule could not be removed."))
                    return
                self.manager.lifecycle_completed(self, result)
            _on_main(apply)

        self.model.perform(request, complete)

    @objc.python_method
    def set_external_lifecycle_pending(self, pending: bool) -> None:
        self._set_busy(
            pending,
            "Removing rule…" if pending else "",
            busy_label="Removing rule" if pending else "")

    @objc.python_method
    def copy_rule_id(self) -> None:
        board = NSPasteboard.generalPasteboard()
        board.clearContents()
        board.setString_forType_(self.rule_id, NSPasteboardTypeString)

    @objc.python_method
    def open_external(self) -> None:
        path = str(self.rule.get("path", ""))
        if path:
            NSWorkspace.sharedWorkspace().openFile_(path)

    @objc.python_method
    def show(self) -> None:
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        if not self._shown:
            self._fit_window_to_content()
            self.reload_compiler_catalog()
            self.reload_validation_results()
            self.reload_deployment_queue()
        self.window.makeKeyAndOrderFront_(None)
        self.window.contentView().layoutSubtreeIfNeeded()
        self._fit_spec_width()
        if not self._shown:
            self.window.center()
            self.window.makeFirstResponder_(self.name_field)
            if self.rule.get("new_draft"):
                self.name_field.selectText_(None)
            self._scroll_content_to_top()
            self._shown = True

    @objc.python_method
    def _scroll_content_to_top(self) -> None:
        clip = self.content_scroll.contentView()
        clip.scrollToPoint_((0, 0))
        self.content_scroll.reflectScrolledClipView_(clip)

    def windowDidResize_(self, _notification):
        self._fit_spec_width()

    def windowShouldClose_(self, _sender):
        if self._advanced_window and _sender == self._advanced_window:
            return True
        if self._busy:
            return False
        if self._queue_is_pending():
            return True
        if not self._dirty:
            return True
        alert = NSAlert.alloc().init()
        alert.setMessageText_("Save this draft before closing?")
        alert.setInformativeText_(
            "Saving keeps your edits local. It does not deploy them.")
        alert.addButtonWithTitle_("Save Draft")
        alert.addButtonWithTitle_("Discard")
        alert.addButtonWithTitle_("Cancel")

        def completed(response):
            if response == NSAlertFirstButtonReturn:
                self._close_after_save = True
                self.save_draft()
            elif response == NSAlertSecondButtonReturn:
                self._dirty = False
                self.window.close()

        alert.beginSheetModalForWindow_completionHandler_(
            self.window, completed)
        return False

    def windowWillClose_(self, notification):
        if self._advanced_window and notification.object() == self._advanced_window:
            self._advanced_window = None
            self._advanced_editor = None
            self._advanced_apply = None
            self._refresh_finding_context()
            return
        if self._finetune_poll_timer:
            self._finetune_poll_timer.cancel()
            self._finetune_poll_timer = None
        if (
            self._deployment_queue_poll_timer
            and not self._queue_is_pending()
        ):
            self._deployment_queue_poll_timer.cancel()
            self._deployment_queue_poll_timer = None
        if self._content_fit_timer:
            self._content_fit_timer.cancel()
            self._content_fit_timer = None
        if self._advanced_window:
            advanced = self._advanced_window
            self._advanced_window = None
            self._advanced_editor = None
            self._advanced_apply = None
            advanced.setDelegate_(None)
            advanced.close()
        if self.manager:
            self.manager.closed(self)


class RuleEditorManager:
    def __init__(
        self,
        model: UIModel,
        on_changed: Callable[[dict[str, Any]], None] | None = None,
        on_show_finding: Callable[[int], None] | None = None,
    ) -> None:
        self.model = model
        self.on_changed = on_changed
        self.on_show_finding = on_show_finding
        self.documents: dict[tuple[str, str], RAPRuleEditorDocument] = {}
        self._pending_sources: set[str] = set()

    def open(self, rule: dict[str, Any], project_root: str) -> None:
        key = (project_root or "", str(rule.get("id", "")))
        document = self.documents.get(key)
        if document is None:
            document = RAPRuleEditorDocument.alloc().init()
            document.configure(self, self.model, rule, project_root)
            self.documents[key] = document
        elif rule.get("_finding_context"):
            document.update_finding_context(rule.get("_finding_context"))
        source_path = str(
            (document.rule.get("definition") or {}).get("source_path", ""))
        if source_path in self._pending_sources:
            document.set_external_lifecycle_pending(True)
        document.show()

    def show_finding(self, finding_id: int) -> None:
        if self.on_show_finding:
            self.on_show_finding(finding_id)

    def validation_cases_changed(
        self, rule_id: str, _project_root: str = ""
    ) -> None:
        for document in self.documents.values():
            if document.rule_id == rule_id:
                document.reload_validation_cases()

    def closed(self, document: RAPRuleEditorDocument) -> None:
        for key, value in list(self.documents.items()):
            if value is document:
                self.documents.pop(key, None)

    def renamed(
        self, document: RAPRuleEditorDocument, old_id: str, new_id: str
    ) -> None:
        self.documents.pop((document.project_root, old_id), None)
        self.documents[(document.project_root, new_id)] = document

    def changed(self, result: dict[str, Any]) -> None:
        if self.on_changed:
            self.on_changed(result)

    def lifecycle_completed(
        self, document: RAPRuleEditorDocument, result: dict[str, Any]
    ) -> None:
        self.definition_removed(document.rule.get("definition") or {})
        self.changed(result)

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
            document._dirty = False
            document.set_external_lifecycle_pending(False)
            document.window.close()
