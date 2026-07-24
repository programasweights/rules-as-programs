"""Intent-first native editor for rule specifications and deployment."""

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
    NSLayoutPriorityDefaultLow,
    NSMinYEdge,
    NSMenu,
    NSMenuItem,
    NSPasteboard,
    NSPasteboardTypeString,
    NSPopover,
    NSPopoverBehaviorTransient,
    NSSearchField,
    NSScrollView,
    NSScreen,
    NSStackView,
    NSStackViewDistributionFill,
    NSToolbar,
    NSToolbarFlexibleSpaceItemIdentifier,
    NSToolbarItem,
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
from Foundation import NSMakeRect, NSMakeSize, NSObject
from PyObjCTools import AppHelper

from .. import rules_api, scaffold
from ..core import revisions
from .layout import fit_rule_editor_layout
from .macos_controls import (
    ButtonRole,
    RAPCommandWindow,
    set_button_symbol,
    style_button,
)
from .macos_views import RAPFlippedView
from .model import UIModel

RUN_OPTIONS = [
    ("message", "Agent replies", "Runs after an assistant reply. Example: check a claim before it reaches you."),
    ("shell_exec", "Command finishes", "Runs after a shell command returns. Example: verify tests or deployment output."),
    ("file_edit", "File changes", "Runs after the agent records a file edit. Example: inspect whether a protected file changed."),
    ("tool_result", "Tool result", "Runs after a non-shell tool responds. Example: validate a browser or API result."),
    ("session_stop", "Turn ends", "Runs when the agent finishes its turn. Example: check the completed work as a whole."),
]
READ_OPTIONS = [
    ("message", "Latest reply", "Reads assistant messages, such as the final claim or explanation."),
    ("thought", "Thoughts", "Reads captured agent reasoning when Cursor exposes it."),
    ("shell_exec", "Commands", "Reads commands and their outputs, such as pytest or git status."),
    ("file_edit", "File edits", "Reads recorded file changes and edited paths."),
    ("tool_result", "Tool results", "Reads results from browser, API, and other non-shell tools."),
]


def _on_main(callback: Callable[[], None]) -> None:
    AppHelper.callAfter(callback)


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
        return [
            "rule.actions", "rule.state",
            NSToolbarFlexibleSpaceItemIdentifier,
            "rule.advanced", "rule.deploy",
        ]

    def toolbarDefaultItemIdentifiers_(self, _toolbar):
        return [
            "rule.actions", "rule.state",
            NSToolbarFlexibleSpaceItemIdentifier,
            "rule.advanced", "rule.deploy",
        ]

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
        self._working_hash = str(rule.get("working_hash", ""))
        self._definition_hash = str(
            (rule.get("definition") or {}).get("source_hash", ""))
        self._saved_source_hash = revisions.hash_source(self.full_source)
        self._source_dirty = bool(
            rule.get("new_draft") or rule.get("draft_changes"))
        self._coverage_dirty = {
            "mode": self.coverage_mode,
            "selected_projects": sorted(
                self.selected_projects
                if self.coverage_mode == "selected" else []),
        } != self._active_coverage
        self._dirty = self._source_dirty or self._coverage_dirty
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
        self.description = str(
            projection.get("description")
            if self.managed_fuzzy else projection.get("spec", ""))
        self.allowed_label = str(projection.get("allowed_label", "OK"))
        self.cases = list(projection.get("cases", []))
        self.on = list(projection.get("on", []))
        self.inputs = list(projection.get("inputs", []))
        self.probes = dict(projection.get("probes", {}))
        self.channel = str(projection.get("channel", "finding"))
        self.severity = str(projection.get("severity", "warn"))
        self.inputs_inferred = bool(projection.get("inputs_inferred"))

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
        self.window.setContentMinSize_(NSMakeSize(680, 520))
        self.window.setTitle_(f"Rule — {self.name}")

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
    def _option_group(self, title: str, options, destination: dict) -> NSStackView:
        heading = self._heading(
            title,
            "Runs when chooses the event that invokes the rule."
            if title == "Runs when"
            else "Reads chooses the evidence included when the rule runs.",
        )
        columns = [self._stack([], vertical=True, spacing=5) for _ in range(2)]
        for index, (kind, label, help_text) in enumerate(options):
            checkbox = NSButton.alloc().init()
            checkbox.setButtonType_(NSButtonTypeSwitch)
            checkbox.setTitle_(label)
            checkbox.setAccessibilityLabel_(label)
            self._wire(
                checkbox,
                lambda sender, value=kind, target=destination: self.toggle_metadata(
                    target, value,
                    sender.state() == NSControlStateValueOn),
            )
            info = self._button(
                "",
                lambda sender, t=label, b=help_text: self.show_info(sender, t, b),
                role="flat",
                accessibility=f"About {label}",
            )
            set_button_symbol(
                info, "info.circle", f"About {label}", fallback="Info")
            row = self._stack([checkbox, info, self._spacer()],
                              vertical=False, spacing=4)
            columns[index % 2].addArrangedSubview_(row)
            destination[kind] = checkbox
        grid = self._stack(columns, vertical=False, spacing=18)
        _activate(
            columns[0].widthAnchor().constraintEqualToAnchor_(columns[1].widthAnchor()))
        return self._stack([heading, grid], vertical=True, spacing=7)

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

        document = NSView.alloc().init()
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
            document.heightAnchor().constraintGreaterThanOrEqualToAnchor_(
                scroll.contentView().heightAnchor()),
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

        if self.finding_context:
            finding = (self.finding_context or {}).get("finding", {})
            self.finding_label = self._label(
                "Tuning from finding: "
                + str(finding.get("message", "")).replace("\n", " "),
                size=10, color=NSColor.secondaryLabelColor(), lines=2)
            content.addArrangedSubview_(self.finding_label)

        spec_heading = self._heading(
            "Rule spec",
            "Describe the behavior to audit in plain language. PAW compiles this "
            "specification into a local rule program.",
        )
        self.advanced_button = self._button(
            "View Python…", lambda _sender: self.show_advanced(),
            role="flat", accessibility="View underlying Python")
        spec_heading.insertArrangedSubview_atIndex_(self.advanced_button, 1)
        content.addArrangedSubview_(spec_heading)
        self.spec_scroll, self.description_editor = self._text_scroll(
            self.description, prose=True, minimum_height=170)
        self.spec_scroll.setContentHuggingPriority_forOrientation_(
            NSLayoutPriorityDefaultLow,
            NSUserInterfaceLayoutOrientationVertical)
        self.spec_scroll.setContentCompressionResistancePriority_forOrientation_(
            NSLayoutPriorityDefaultLow,
            NSUserInterfaceLayoutOrientationVertical)
        self.description_editor.setAccessibilityLabel_("Rule specification")
        content.addArrangedSubview_(self.spec_scroll)
        self.custom_label = self._label(
            "This is a custom Python rule. Edit its behavior through View Python.",
            size=11, color=NSColor.systemOrangeColor(), lines=2)
        content.addArrangedSubview_(self.custom_label)

        content.addArrangedSubview_(self._heading(
            "Runs in",
            "All projects includes current and future projects. Selected projects "
            "runs only in the projects you choose.",
        ))
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

        self.trigger_buttons: dict[str, NSButton] = {}
        self.input_buttons: dict[str, NSButton] = {}
        self.triggers_group = self._option_group(
            "Runs when", RUN_OPTIONS, self.trigger_buttons)
        self.inputs_group = self._option_group(
            "Reads", READ_OPTIONS, self.input_buttons)
        self.metadata_stack = self._stack(
            [self.triggers_group, self.inputs_group],
            vertical=True,
            spacing=16,
        )
        content.addArrangedSubview_(self.metadata_stack)
        self.inferred_label = self._label(
            "Inputs are inferred from the Python source.",
            size=10, color=NSColor.secondaryLabelColor())
        content.addArrangedSubview_(self.inferred_label)

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
        self.footer_advanced = self._button(
            "Advanced…", lambda _sender: self.show_advanced(), role="flat")
        self.deploy_button = self._button(
            "Deploy", lambda _sender: self.deploy(), role="primary")
        toolbar = NSToolbar.alloc().initWithIdentifier_("RuleEditorToolbar")
        toolbar.setDelegate_(self._toolbar_delegate)
        toolbar.setAllowsUserCustomization_(False)
        self.window.setToolbar_(toolbar)
        self.toolbar = toolbar
        self._interactive_controls = [
            self.name_field,
            self.description_editor,
            self.all_projects_radio,
            self.selected_projects_radio,
            self.edit_projects_button,
            self.advanced_button,
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
            self.description_editor,
            self.all_projects_radio,
            self.selected_projects_radio,
            self.edit_projects_button,
            *self.trigger_buttons.values(),
            *self.input_buttons.values(),
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
            self.description = str(self.description_editor.string()).strip()

    @objc.python_method
    def _compose(self) -> tuple[bool, str, str]:
        self._capture()
        if self.custom:
            ok, source, error = rules_api.patch_rule_identity(
                self.full_source, self.rule_id, self.name)
            return ok, source, error
        if self.managed_fuzzy:
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
            function_source=rules_api.source_projection(
                self.full_source).get("function_source", ""),
            spec=self.description or None,
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
        for kind, button in self.trigger_buttons.items():
            button.setState_(
                NSControlStateValueOn if kind in self.on
                else NSControlStateValueOff)
        for kind, button in self.input_buttons.items():
            button.setState_(
                NSControlStateValueOn if kind in self.inputs
                else NSControlStateValueOff)
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
        self.custom_label.setHidden_(not self.custom)
        self.metadata_stack.setHidden_(self.custom)
        self.inferred_label.setHidden_(
            self.custom or not self.inputs_inferred)
        self.description_editor.setEditable_(not self.custom and not self._busy)
        self.lifecycle_button.setTitle_(self._lifecycle_title())
        if self._busy:
            state = "Deploying"
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
            or not self._active_hash
            or (
                self._working_hash
                and self._working_hash != self._active_hash
            )
        )
        impact = (
            len([
                item for item in self.projects
                if (
                    item.get("path") not in self.project_overrides
                    or (
                        self.source_scope == "project"
                        and item.get("path") == self.project_root
                    )
                )
            ])
            if self.coverage_mode == "all"
            else len([
                path for path in self.selected_projects
                if (
                    path not in self.project_overrides
                    or (
                        self.source_scope == "project"
                        and path == self.project_root
                    )
                )
            ])
        )
        self.footer_status.setStringValue_(
            state
            + (
                f" · Updates {impact} project"
                f"{'s' if impact != 1 else ''}"
                if deploy_needed else ""
            )
        )
        self.deploy_button.setEnabled_(deploy_needed and not self._busy)
        self.deploy_button.setTitle_(
            "Deploy" if deploy_needed else "Deployed")
        self._recalculate_key_loop()
        self._programmatic = False

    @objc.python_method
    def editor_changed(self) -> None:
        if self._programmatic or self._busy:
            return
        self._capture()
        ok, source, _error = self._compose()
        self._source_dirty = (
            not ok or revisions.hash_source(source) != self._saved_source_hash)
        self._dirty = self._source_dirty or self._coverage_dirty
        self.rule["_deploy_failed"] = False
        self.window.setDocumentEdited_(True)
        self._refresh_ui()

    @objc.python_method
    def coverage_changed(self) -> None:
        if self._programmatic or self._busy:
            return
        current = {
            "mode": self.coverage_mode,
            "selected_projects": sorted(
                self.selected_projects
                if self.coverage_mode == "selected" else []),
        }
        self._coverage_dirty = current != self._active_coverage
        self._dirty = self._source_dirty or self._coverage_dirty
        self.rule["_deploy_failed"] = False
        self.window.setDocumentEdited_(True)
        self._refresh_ui()

    @objc.python_method
    def toggle_metadata(
        self, values: list[str], value: str, enabled: bool
    ) -> None:
        if enabled and value not in values:
            values.append(value)
        elif not enabled and value in values:
            values.remove(value)
        self.editor_changed()

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
        self._dirty = True
        self.window.setDocumentEdited_(True)
        self._advanced_window.close()
        self._advanced_window = None
        self._advanced_editor = None
        self._advanced_apply = None
        self._refresh_ui(sync_text=not self.custom)

    @objc.python_method
    def _set_busy(self, busy: bool, status: str = "") -> None:
        self._busy = busy
        for control in self._interactive_controls:
            if hasattr(control, "setEnabled_"):
                control.setEnabled_(not busy)
        if hasattr(self.description_editor, "setEditable_"):
            self.description_editor.setEditable_(not busy and not self.custom)
        if self._advanced_editor:
            self._advanced_editor.setEditable_(not busy)
        if self._advanced_apply:
            self._advanced_apply.setEnabled_(not busy)
        if status:
            self.diagnostics_label.setStringValue_(status)
            self.diagnostics_label.setHidden_(False)
        self._refresh_ui()

    @objc.python_method
    def deploy(self) -> None:
        if self._busy or not self.deploy_button.isEnabled():
            return
        if not self._active_hash and not self._scope_confirmed:
            self.show_projects_sheet(on_confirm=self.deploy)
            return
        ok, source, error = self._compose()
        if not ok:
            self._deployment_failed(error)
            return
        source_hash = revisions.hash_source(source)
        source_changed = source_hash != self._active_hash
        self._set_busy(True, "Validating, testing, and compiling…")

        def prepared(result: dict[str, Any]) -> None:
            def apply() -> None:
                if not result.get("ok"):
                    self._deployment_failed(
                        result.get("error", "Deployment preparation failed."))
                    return
                self.diagnostics_label.setStringValue_(
                    "Activating revision and project coverage…")
                self.model.perform({
                    "type": "commit_deployment",
                    "token": result["token"],
                }, committed, timeout=30)
            _on_main(apply)

        def committed(result: dict[str, Any]) -> None:
            def apply() -> None:
                if not result.get("ok"):
                    self._deployment_failed(
                        result.get("error", "Deployment failed."))
                    return
                old_id = self.rule_id
                info = dict(result.get("rule") or {})
                info["projection"] = rules_api.source_projection(
                    info.get("source", source))
                info["deployment"] = {
                    "coverage": result.get("coverage") or {},
                    "projects": self.projects,
                    "impact_count": result.get("impact_count", 0),
                }
                self.rule.update(info)
                self.source_scope = str(info.get("scope", "global"))
                self.rule["new_draft"] = False
                self.rule_id = str(info.get("id", self.rule_id))
                self.full_source = str(info.get("source", source))
                self._apply_projection(info["projection"])
                coverage = result.get("coverage") or {}
                self.coverage_mode = str(
                    coverage.get("mode", self.coverage_mode))
                self.selected_projects = list(
                    coverage.get("selected_projects") or [])
                self._active_coverage = {
                    "mode": self.coverage_mode,
                    "selected_projects": sorted(
                        self.selected_projects
                        if self.coverage_mode == "selected" else []),
                }
                self._active_hash = str(
                    (result.get("active") or {}).get("source_hash", ""))
                self._working_hash = str(
                    info.get("working_hash", self._active_hash))
                self._definition_hash = str(
                    (info.get("definition") or {}).get("source_hash", ""))
                self._saved_source_hash = revisions.hash_source(self.full_source)
                self._source_dirty = False
                self._coverage_dirty = False
                self._dirty = False
                self.rule["_deploy_failed"] = False
                self.window.setDocumentEdited_(False)
                self.window.setTitle_(f"Rule — {self.name}")
                self.diagnostics_label.setStringValue_(
                    f"Deployed to {result.get('impact_count', 0)} project(s).")
                self._set_busy(False)
                self._refresh_ui(sync_text=True)
                if self.manager:
                    if old_id != self.rule_id:
                        self.manager.renamed(self, old_id, self.rule_id)
                    self.manager.changed(result)
            _on_main(apply)

        self.model.perform({
            "type": "prepare_deployment",
            "rule_id": self.rule_id,
            "project_root": self.project_root,
            "source": source,
            "source_changed": source_changed,
            "expected_active_hash": self._active_hash,
            "coverage": {
                "mode": self.coverage_mode,
                "selected_projects": self.selected_projects,
            },
        }, prepared, timeout=180)

    @objc.python_method
    def _deployment_failed(self, error: str) -> None:
        self.rule["_deploy_failed"] = True
        self.diagnostics_label.setStringValue_(
            f"Deploy failed. The previous deployment is still active.\n{error}")
        self.diagnostics_label.setHidden_(False)
        self._set_busy(False)

    @objc.python_method
    def save_draft(self) -> None:
        if self._busy:
            return
        ok, source, error = self._compose()
        if not ok:
            self._deployment_failed(error)
            return
        self._set_busy(True, "Saving local draft…")
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
                },
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
                },
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
                self._dirty = self._coverage_dirty
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
        self._set_busy(pending, "Removing rule…" if pending else "")

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
        self.window.makeKeyAndOrderFront_(None)
        self.window.contentView().layoutSubtreeIfNeeded()
        self._fit_spec_width()
        if not self._shown:
            self.window.center()
            self.window.makeFirstResponder_(self.name_field)
            if self.rule.get("new_draft"):
                self.name_field.selectText_(None)
            self._shown = True

    def windowDidResize_(self, _notification):
        self._fit_spec_width()

    def windowShouldClose_(self, _sender):
        if self._advanced_window and _sender == self._advanced_window:
            return True
        if self._busy:
            return False
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
            return
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
    ) -> None:
        self.model = model
        self.on_changed = on_changed
        self.documents: dict[tuple[str, str], RAPRuleEditorDocument] = {}
        self._pending_sources: set[str] = set()

    def open(self, rule: dict[str, Any], project_root: str) -> None:
        key = (project_root or "", str(rule.get("id", "")))
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
