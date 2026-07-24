"""Native macOS menu-bar application.

This is a real ``NSStatusItem`` with an anchored ``NSPopover``.  It does not
attach a custom view to ``NSMenu`` and never runs a modal alert loop, avoiding
the greyed/invisible behavior of the old rumps implementation.
"""

from __future__ import annotations

import io
import os
import subprocess
from pathlib import Path
from typing import Any, Callable

import objc
from AppKit import (
    NSApplication,
    NSApplicationActivationPolicyAccessory,
    NSColor,
    NSFont,
    NSFontAttributeName,
    NSForegroundColorAttributeName,
    NSImage,
    NSImageLeft,
    NSMenu,
    NSMenuItem,
    NSMinYEdge,
    NSEventModifierFlagCommand,
    NSEventModifierFlagControl,
    NSEventModifierFlagShift,
    NSPasteboard,
    NSPasteboardTypeString,
    NSPopover,
    NSPopoverBehaviorTransient,
    NSStatusBar,
    NSVariableStatusItemLength,
    NSViewController,
    NSWorkspace,
)
from Foundation import NSMakeSize, NSMutableAttributedString, NSObject
from Foundation import NSData
from PyObjCTools import AppHelper

from .. import config
from .macos_views import POPOVER_HEIGHT, POPOVER_WIDTH, PopoverRenderer
from .model import UIModel, UISnapshot, demo_snapshot
from .status import StatusPresentation, status_presentation

_CONTROLLER = None
_PAW_ALPHA = None
_PAW_TEMPLATE = None


def _on_main(callback: Callable[[], None]) -> None:
    AppHelper.callAfter(callback)


def _open_path(path: str) -> None:
    if path:
        NSWorkspace.sharedWorkspace().openFile_(str(path))


def _open_in_cursor(path: str) -> None:
    if not path:
        return
    try:
        subprocess.Popen(["open", "-a", "Cursor", path])
    except OSError:
        _open_path(path)


def _copy_text(text: str) -> None:
    pasteboard = NSPasteboard.generalPasteboard()
    pasteboard.clearContents()
    pasteboard.setString_forType_(text, NSPasteboardTypeString)


def _paw_template_image() -> NSImage | None:
    """Return a large template paw that macOS tints for menu-bar contrast."""
    global _PAW_ALPHA, _PAW_TEMPLATE
    if _PAW_TEMPLATE is not None:
        return _PAW_TEMPLATE
    try:
        from PIL import Image
        if _PAW_ALPHA is None:
            source = Image.open(config.icon_png()).convert("RGBA")
            alpha = source.getchannel("A")
            bounds = alpha.getbbox()
            _PAW_ALPHA = alpha.crop(bounds) if bounds else alpha
        scale = 2
        width_pt = height_pt = 22
        canvas = Image.new(
            "RGBA", (width_pt * scale, height_pt * scale), (0, 0, 0, 0))
        paw_alpha = _PAW_ALPHA.resize((21 * scale, 21 * scale), Image.Resampling.LANCZOS)
        paw = Image.new("RGBA", paw_alpha.size, (0, 0, 0, 255))
        paw.putalpha(paw_alpha)
        canvas.alpha_composite(paw, (0, 0))
        buffer = io.BytesIO()
        canvas.save(buffer, format="PNG")
        raw = buffer.getvalue()
        data = NSData.dataWithBytes_length_(raw, len(raw))
        image = NSImage.alloc().initWithData_(data)
        image.setSize_(NSMakeSize(width_pt, height_pt))
        image.setTemplate_(True)
        _PAW_TEMPLATE = image
        return image
    except Exception:
        return None


def _status_attributed_title(
    presentation: StatusPresentation,
) -> NSMutableAttributedString:
    result = NSMutableAttributedString.alloc().init()
    font = NSFont.boldSystemFontOfSize_(13)

    def append(text: str, color) -> None:
        piece = NSMutableAttributedString.alloc().initWithString_attributes_(
            text,
            {
                NSForegroundColorAttributeName: color,
                NSFontAttributeName: font,
            },
        )
        result.appendAttributedString_(piece)

    if presentation.kind == "finding":
        color = {
            "info": NSColor.systemBlueColor(),
            "warn": NSColor.systemYellowColor(),
            "critical": NSColor.systemRedColor(),
        }.get(presentation.severity or "info", NSColor.systemBlueColor())
        append(f" {presentation.badge_text}", color)
    elif presentation.kind == "attention":
        append(" ?", NSColor.systemPurpleColor())
    elif presentation.kind == "paused":
        append(" ‖", NSColor.secondaryLabelColor())
    elif presentation.kind == "unavailable":
        append(" !", NSColor.systemRedColor())
    elif presentation.kind == "degraded":
        append(" !", NSColor.systemOrangeColor())
    if (
        presentation.attention_count
        and presentation.kind not in ("attention", "unavailable", "paused")
    ):
        append(" ?", NSColor.systemPurpleColor())
    return result


class RAPStatusTarget(NSObject):
    def toggle_(self, sender):
        owner = getattr(self, "owner", None)
        if owner:
            owner.toggle_popover(sender)


class MacOSController(NSObject):
    """Application delegate and navigation/controller layer."""

    def init(self):
        self = objc.super(MacOSController, self).init()
        if self is None:
            return None
        self.route = "inbox"
        self.inbox_mode = "open"
        self.history_groups: list[dict[str, Any]] = []
        self.history_loading = False
        self.selected_finding: dict[str, Any] | None = None
        self.finding_detail: dict[str, Any] | None = None
        self.detail_loading = False
        self.detail_error = ""
        self.show_raw_trace = False
        self.home_project = ""
        self.rules_context = "library"
        self.selected_project = ""
        self.rules_data: dict[str, Any] = {}
        self.rules_loading = False
        self.rules_filter = ""
        self._rules_request_token = 0
        self.banner = ""
        self.confirmation: dict[str, Any] | None = None
        self.snapshot = UISnapshot.loading()
        self.status_item = None
        self.popover = None
        self.content_controller = None
        self.content_view = None
        self._last_popover_size = None
        self.renderer = PopoverRenderer(self)
        self.model = UIModel(listener=self._snapshot_received)
        self._status_target = RAPStatusTarget.alloc().init()
        self._status_target.owner = self
        self._studio = None
        self._inspector = None
        self.demo = False
        return self

    # --- application lifecycle ----------------------------------------
    def applicationDidFinishLaunching_(self, _notification):
        app = NSApplication.sharedApplication()
        app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)
        self._build_main_menu()
        self._build_status_item()
        self._build_popover()
        self._render()
        if self.demo:
            self._apply_snapshot(demo_snapshot())
        else:
            self.model.start()

    def applicationWillTerminate_(self, _notification):
        self.model.stop()

    @objc.python_method
    def _build_main_menu(self) -> None:
        """Install responder-chain editing commands for this nib-less app."""
        main = NSMenu.alloc().initWithTitle_("Rules as Programs")

        app_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Rules as Programs", None, "")
        app_menu = NSMenu.alloc().initWithTitle_("Rules as Programs")
        quit_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Quit Rules as Programs", "terminate:", "q")
        quit_item.setTarget_(None)
        quit_item.setKeyEquivalentModifierMask_(NSEventModifierFlagCommand)
        app_menu.addItem_(quit_item)
        app_item.setSubmenu_(app_menu)
        main.addItem_(app_item)

        edit_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Edit", None, "")
        edit_menu = NSMenu.alloc().initWithTitle_("Edit")

        def add(
            title: str, action: str, key: str, modifiers: int
        ) -> None:
            item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                title, action, key)
            # A nil target is intentional: AppKit forwards the selector to the
            # active field editor or text view through the responder chain.
            item.setTarget_(None)
            item.setKeyEquivalentModifierMask_(modifiers)
            edit_menu.addItem_(item)

        add("Undo", "undo:", "z", NSEventModifierFlagCommand)
        add(
            "Redo", "redo:", "z",
            NSEventModifierFlagCommand | NSEventModifierFlagShift)
        edit_menu.addItem_(NSMenuItem.separatorItem())
        add("Cut", "cut:", "x", NSEventModifierFlagCommand)
        add("Copy", "copy:", "c", NSEventModifierFlagCommand)
        add("Paste", "paste:", "v", NSEventModifierFlagCommand)
        add("Select All", "selectAll:", "a", NSEventModifierFlagCommand)
        add("Select All (Control-A)", "selectAll:", "a", NSEventModifierFlagControl)

        edit_item.setSubmenu_(edit_menu)
        main.addItem_(edit_item)
        NSApplication.sharedApplication().setMainMenu_(main)

    @objc.python_method
    def _build_status_item(self) -> None:
        self.status_item = NSStatusBar.systemStatusBar().statusItemWithLength_(
            NSVariableStatusItemLength)
        self.status_item.setHighlightMode_(True)
        button = self.status_item.button()
        image = _paw_template_image()
        if image:
            button.setImage_(image)
            button.setImagePosition_(NSImageLeft)
            button.setAttributedTitle_(
                _status_attributed_title(status_presentation(self.snapshot)))
        else:
            button.setTitle_("RAP")
        button.setTarget_(self._status_target)
        button.setAction_("toggle:")
        button.setAccessibilityLabel_("Rules as Programs")

    @objc.python_method
    def _build_popover(self) -> None:
        self.content_controller = NSViewController.alloc().init()
        self.popover = NSPopover.alloc().init()
        self.popover.setBehavior_(NSPopoverBehaviorTransient)
        self.popover.setAnimates_(True)
        self.popover.setDelegate_(self)
        self.popover.setContentSize_(NSMakeSize(POPOVER_WIDTH, POPOVER_HEIGHT))
        self.popover.setContentViewController_(self.content_controller)

    @objc.python_method
    def toggle_popover(self, sender) -> None:
        if self.popover.isShown():
            self.popover.performClose_(sender)
            return
        self._show_popover()

    @objc.python_method
    def _show_popover(self) -> None:
        if not self.popover or not self.status_item or self.popover.isShown():
            return
        self._render()
        button = self.status_item.button()
        self.popover.showRelativeToRect_ofView_preferredEdge_(
            button.bounds(), button, NSMinYEdge)
        button.setHighlighted_(True)
        window = self.popover.contentViewController().view().window()
        if window:
            window.makeKeyWindow()

    @objc.python_method
    def defer_menu_action(self, callback: Callable[[], None]) -> None:
        """Run after NSMenu tracking ends so popover mutations remain visible."""
        _on_main(callback)

    def popoverWillShow_(self, _notification):
        if self.status_item:
            self.status_item.button().setHighlighted_(True)

    def popoverDidClose_(self, _notification):
        if self.status_item:
            self.status_item.button().setHighlighted_(False)

    @objc.python_method
    def quit(self) -> None:
        NSApplication.sharedApplication().terminate_(None)

    # --- snapshot/render ------------------------------------------------
    @objc.python_method
    def _snapshot_received(self, snapshot: UISnapshot) -> None:
        _on_main(lambda: self._apply_snapshot(snapshot))

    @objc.python_method
    def _apply_snapshot(self, snapshot: UISnapshot) -> None:
        self.snapshot = snapshot
        if not self.selected_project and snapshot.projects:
            active = next(
                (project for project in snapshot.projects if project.get("active")),
                snapshot.projects[0],
            )
            self.selected_project = active.get("path", "")
        self._update_status_item()
        if self.popover and self.popover.isShown():
            self._render()

    @objc.python_method
    def _update_status_item(self) -> None:
        if not self.status_item:
            return
        button = self.status_item.button()
        presentation = status_presentation(self.snapshot)
        image = _paw_template_image()
        if image:
            button.setImage_(image)
            button.setTitle_("")
            button.setAttributedTitle_(_status_attributed_title(presentation))
        else:
            button.setTitle_(presentation.badge_text or "RAP")
        button.setToolTip_(presentation.tooltip)
        button.setAccessibilityLabel_(presentation.accessibility)

    @objc.python_method
    def _render(self) -> None:
        if not self.content_controller:
            return
        max_height = 600.0
        if self.status_item and self.status_item.button().window():
            screen = self.status_item.button().window().screen()
            if screen:
                max_height = max(
                    170.0, min(600.0, screen.visibleFrame().size.height - 48.0))
        self.content_view, size = self.renderer.render(
            self.snapshot, max_height=max_height)
        self.content_controller.setView_(self.content_view)
        if self.popover and size != self._last_popover_size:
            self.popover.setContentSize_(NSMakeSize(*size))
            self._last_popover_size = size

    @objc.python_method
    def _set_banner(self, message: str) -> None:
        self.banner = message
        self._render()

    @objc.python_method
    def retry(self) -> None:
        self.banner = ""
        self.model.refresh()

    @objc.python_method
    def request_confirmation(
        self, title: str, message: str, confirm_title: str,
        callback: Callable[[], None], *, destructive: bool = False,
    ) -> None:
        self.confirmation = {
            "title": title,
            "message": message,
            "confirm_title": confirm_title,
            "callback": callback,
            "destructive": destructive,
        }
        self._render()
        # Menu selection can dismiss a transient popover after its action
        # returns. Re-show on the next AppKit turn so the confirmation cannot
        # disappear behind the menu-tracking loop.
        _on_main(self._show_popover)

    @objc.python_method
    def cancel_confirmation(self) -> None:
        self.confirmation = None
        self._render()

    @objc.python_method
    def confirm_change(self) -> None:
        confirmation = self.confirmation or {}
        callback = confirmation.get("callback")
        self.confirmation = None
        if callback:
            callback()
        self._render()

    # --- navigation -----------------------------------------------------
    @objc.python_method
    def select_tab(self, tab: str) -> None:
        self.route = tab
        self.banner = ""
        if tab == "rules":
            self._load_rules()
        self._render()

    @objc.python_method
    def select_home_project(self, project_root: str) -> None:
        self.home_project = project_root
        self._render()

    @objc.python_method
    def open_manage_rules(self, project_root: str) -> None:
        self.rules_context = "project"
        self.selected_project = project_root
        self.route = "rules"
        self._load_rules()
        self._render()

    @objc.python_method
    def open_rules_for_current(self, sender=None) -> None:
        project_root = self.home_project or self.selected_project
        if project_root:
            self.open_manage_rules(project_root)
            return
        items = [
            (
                project.get("name") or Path(project.get("path", "")).name,
                lambda path=project.get("path", ""): self.open_manage_rules(path),
                bool(project.get("path")),
            )
            for project in self.snapshot.projects
        ]
        self.renderer.popup_menu(sender, items)

    @objc.python_method
    def open_rule_library(self) -> None:
        self.rules_context = "library"
        self.route = "rules"
        self._load_rules()
        self._render()

    @objc.python_method
    def filter_rules(self, text: str) -> None:
        self.rules_filter = text
        self._render()

    @objc.python_method
    def show_rule_list_menu(self, sender) -> None:
        self.renderer.popup_menu(sender, [
            ("Use global defaults", self.reset_rule_assignments, True),
            ("Run all in this project",
             lambda: self.bulk_rule_assignments(True), True),
            ("Stop all in this project",
             lambda: self.bulk_rule_assignments(False), True),
        ])

    @objc.python_method
    def begin_add_rule(self, project_root: str, sender=None) -> None:
        if project_root:
            self.selected_project = project_root
            self._new_rule(project_root)
            return
        projects = self.snapshot.projects
        items = [
            (
                project.get("name") or Path(project.get("path", "")).name,
                lambda path=project.get("path", ""): self.begin_add_rule(path),
                bool(project.get("path")),
            )
            for project in projects
        ]
        self.renderer.popup_menu(sender, items)

    @objc.python_method
    def set_inbox_mode(self, mode: str) -> None:
        self.inbox_mode = mode
        if mode == "history":
            self.history_loading = True
            self._render()

            def complete(result: dict[str, Any]) -> None:
                def apply() -> None:
                    self.history_loading = False
                    if result.get("ok"):
                        groups = result.get("groups", [])
                        self.history_groups = [
                            group for group in groups
                            if group.get("acknowledged") or group.get("suppressed")
                        ]
                    else:
                        self._set_banner(result.get("error", "History could not be loaded."))
                    self._render()
                _on_main(apply)

            self.model.perform({
                "type": "finding_groups",
                "reviewed_only": True,
                "limit": 5000,
            }, complete)
        else:
            self._render()

    @objc.python_method
    def open_finding(self, group: dict[str, Any]) -> None:
        self.selected_finding = group
        self.finding_detail = None
        self.detail_loading = True
        self.detail_error = ""
        self.show_raw_trace = False
        self._set_banner("Loading finding context…")

        def complete(result: dict[str, Any]) -> None:
            def apply() -> None:
                self.detail_loading = False
                if result.get("ok"):
                    self.finding_detail = result
                    from .finding_inspector import FindingInspectorManager
                    if self._inspector is None:
                        self._inspector = FindingInspectorManager(
                            self.model, self.edit_rule)
                    self._inspector.open(result)
                    self.banner = ""
                    if self.popover and self.popover.isShown():
                        self.popover.performClose_(None)
                else:
                    self.detail_error = result.get("error", "Evidence could not be loaded.")
                    self._set_banner(self.detail_error)
            _on_main(apply)

        self.model.perform(
            {"type": "finding_detail", "id": group.get("id")}, complete)

    @objc.python_method
    def close_finding(self) -> None:
        self.route = "inbox"
        self.selected_finding = None
        self.finding_detail = None
        self.detail_loading = False
        self.detail_error = ""
        self._render()

    @objc.python_method
    def toggle_raw_trace(self) -> None:
        self.show_raw_trace = not self.show_raw_trace
        self._render()

    # --- finding actions ------------------------------------------------
    @objc.python_method
    def done_group(self, group: dict[str, Any]) -> None:
        ids = [int(value) for value in (group.get("ids") or [group.get("id")]) if value]

        def complete(result: dict[str, Any]) -> None:
            def apply() -> None:
                if result.get("ok"):
                    if self.route == "finding":
                        self.close_finding()
                else:
                    self.detail_error = result.get("error", "Finding could not be marked Done.")
                    self._render()
            _on_main(apply)

        self.model.done(ids, complete)

    @objc.python_method
    def done_project(self, project_root: str) -> None:
        self.model.done_project(
            project_root,
            lambda result: _on_main(lambda: self._set_banner(
                "" if result.get("ok") else result.get("error", "Could not mark findings Done."))),
        )

    @objc.python_method
    def dismiss_attention(self, item: dict[str, Any]) -> None:
        self.model.perform(
            {"type": "dismiss_attention", "id": item.get("id")},
            lambda result: _on_main(lambda: (
                self.model.refresh() if result.get("ok")
                else self._set_banner(
                    result.get("error", "Could not clear attention state."))
            )),
        )

    @objc.python_method
    def open_attention_project(self, item: dict[str, Any]) -> None:
        _open_in_cursor(item.get("project_root", ""))

    @objc.python_method
    def _mute(self, group: dict[str, Any]) -> None:
        self.model.mute_rule(
            group.get("rule_id", ""),
            group.get("project_root", ""),
            lambda result: _on_main(lambda: self._set_banner(
                "Future findings are hidden in this project. "
                "The current finding remains until reviewed."
                if result.get("ok") else result.get(
                    "error", "Could not hide future findings."))),
        )

    @objc.python_method
    def _reopen(self, group: dict[str, Any]) -> None:
        self.model.perform(
            {"type": "reopen", "fingerprint": group.get("fingerprint")},
            lambda result: _on_main(lambda: (
                self.set_inbox_mode("open") if result.get("ok")
                else self._set_banner(result.get("error", "Could not reopen finding."))
            )),
        )

    @objc.python_method
    def _review_with_reason(self, group: dict[str, Any], reason: str) -> None:
        ids = [int(value) for value in (group.get("ids") or [group.get("id")]) if value]
        self.model.perform(
            {"type": "review", "ids": ids, "reason": reason},
            lambda result: _on_main(lambda: (
                self.close_finding() if result.get("ok") and self.route == "finding"
                else self.model.refresh() if result.get("ok")
                else self._set_banner(result.get("error", "Finding could not be reviewed."))
            )),
        )

    @objc.python_method
    def show_finding_menu(self, sender, group: dict[str, Any]) -> None:
        history = self.inbox_mode == "history"
        items: list[tuple[str, Callable[[], None], bool]] = []
        if history:
            if group.get("review_reason") == "rule_deleted":
                items.append(("Rule deleted — history only", lambda: None, False))
            elif group.get("suppressed"):
                items.append((
                    "Show future findings",
                    lambda: self.model.perform({
                        "type": "unmute",
                        "rule_id": group.get("rule_id"),
                        "project_root": group.get("project_root"),
                    }, lambda result: _on_main(lambda: self._set_banner(
                        "Future findings will be shown." if result.get("ok")
                        else result.get("error", "Could not show future findings.")))),
                    True,
                ))
            else:
                items.append(("Reopen finding", lambda: self._reopen(group), True))
        else:
            items.extend([
                ("Mark reviewed", lambda: self.done_group(group), True),
                ("Tune rule…", lambda: self.edit_rule({
                    "id": group.get("rule_id"),
                    "project_root": group.get("project_root"),
                }), True),
                ("Hide future findings in this project",
                 lambda: self._mute(group), True),
                ("-", lambda: None, True),
                ("Done as false positive", lambda: self._review_with_reason(
                    group, "false_positive"), True),
                ("Done as acceptable risk", lambda: self._review_with_reason(
                    group, "acceptable_risk"), True),
            ])
        items.extend([
            ("-", lambda: None, True),
            ("Open raw audit log", lambda: _open_path(str(
                config.project_log_file(group.get("project_root", "")))), True),
            ("Copy finding JSON", lambda: _copy_text(
                __import__("json").dumps(
                    self.finding_detail or group, indent=2, ensure_ascii=False,
                    default=str)), True),
            ("Copy project path", lambda: _copy_text(group.get("project_root", "")), True),
        ])
        self.renderer.popup_menu(sender, items)

    # --- rules ----------------------------------------------------------
    @objc.python_method
    def select_project(self, project_root: str) -> None:
        self.rules_context = "project" if project_root else "library"
        if project_root:
            self.selected_project = project_root
        self._load_rules()

    @objc.python_method
    def _load_rules(self) -> None:
        self.rules_loading = True
        self._rules_request_token += 1
        token = self._rules_request_token
        requested_context = self.rules_context
        requested_project = (
            self.selected_project if requested_context == "project" else "")
        self._render()

        def complete(result: dict[str, Any]) -> None:
            def apply() -> None:
                if (
                    token != self._rules_request_token
                    or requested_context != self.rules_context
                    or (
                        requested_context == "project"
                        and requested_project != self.selected_project
                    )
                ):
                    return
                self.rules_loading = False
                if result.get("ok"):
                    self.rules_data = result
                else:
                    self._set_banner(result.get("error", "Rules could not be loaded."))
                self._render()
            _on_main(apply)

        request = (
            {"type": "rule_library"}
            if requested_context == "library"
            else {"type": "rules", "project_root": requested_project}
        )
        self.model.perform(request, complete)

    @objc.python_method
    def toggle_rule(self, rule: dict[str, Any], enabled: bool) -> None:
        # Project assignment is reversible and intentionally does not use a
        # destructive confirmation dialog.
        self._set_rule_enabled(rule, enabled)

    @objc.python_method
    def _set_rule_enabled(self, rule: dict[str, Any], enabled: bool) -> None:
        self.model.set_rule_enabled(
            rule.get("id", ""), self.selected_project, enabled,
            name=rule.get("name") or rule.get("title") or "",
            callback=lambda result: _on_main(lambda: (
                self._load_rules() if result.get("ok")
                else self._set_banner(result.get("error", "Rule state could not be changed."))
            )),
        )

    @objc.python_method
    def reset_rule_assignments(self) -> None:
        self.model.perform({
            "type": "reset_project_assignments",
            "project_root": self.selected_project,
        }, lambda result: _on_main(lambda: (
            self._load_rules() if result.get("ok")
            else self._set_banner(result.get("error", "Could not reset assignments."))
        )))

    @objc.python_method
    def bulk_rule_assignments(self, enabled: bool) -> None:
        assignments = {
            rule["id"]: enabled for rule in (self.rules_data or {}).get("rules", [])
            if rule.get("id")
        }
        self.model.perform({
            "type": "set_project_assignments",
            "project_root": self.selected_project,
            "assignments": assignments,
        }, lambda result: _on_main(lambda: (
            self._load_rules() if result.get("ok")
            else self._set_banner(result.get("error", "Could not update assignments."))
        )))

    @objc.python_method
    def _unmute_rule(self, rule: dict[str, Any]) -> None:
        project_root = self._rule_project_root(rule)
        self.model.perform({
            "type": "unmute",
            "rule_id": rule.get("id"),
            "project_root": project_root,
        }, lambda result: _on_main(lambda: (
            self._load_rules() if result.get("ok")
            else self._set_banner(
                result.get("error", "Could not show future findings."))
        )))

    @objc.python_method
    def _rule_project_root(self, rule: dict[str, Any]) -> str:
        definition = rule.get("definition") or {}
        if definition.get("project_root"):
            return str(definition["project_root"])
        if "project_root" in rule:
            return str(rule.get("project_root") or "")
        return self.selected_project if self.rules_context == "project" else ""

    @objc.python_method
    def _delete_action_title(self, rule: dict[str, Any]) -> str:
        if rule.get("is_builtin"):
            return "Remove installed built-in copy…"
        definition = rule.get("definition") or {}
        if definition.get("scope") == "project":
            return "Delete project rule…"
        return "Delete shared rule…"

    @objc.python_method
    def open_rule_source(self, rule: dict[str, Any]) -> None:
        _open_path(str(rule.get("source_path", "")))

    @objc.python_method
    def show_rule_menu(self, sender, rule: dict[str, Any]) -> None:
        invalid = bool(rule.get("invalid"))
        items: list[tuple[str, Callable[[], None], bool]] = []
        if not invalid:
            items.extend([
                (
                    "Edit shared rule…" if rule.get("scope") == "global"
                    else "Edit in Rule Editor…",
                    lambda: self.edit_rule(rule),
                    True,
                ),
                ("Test rule", lambda: self._test_rule_quick(rule), True),
                (
                    "Show future findings",
                    lambda: self._unmute_rule(rule),
                    bool(rule.get("muted")),
                ),
            ])
        items.extend([
            ("Open Python file",
             lambda: _open_path(rule.get("source_path", "")), True),
            ("Copy Python path",
             lambda: _copy_text(rule.get("source_path", "")), True),
        ])
        project_context = self.rules_context == "project"
        if (
            not invalid
            and rule.get("scope") == "global"
            and project_context
            and self.selected_project
        ):
            items.insert(
                1,
                ("Customize for this project…",
                 lambda: self._create_project_override(rule), True),
            )
        elif (
            not invalid
            and rule.get("scope") == "project"
            and not rule.get("customized_from")
        ):
            items.insert(
                1,
                ("Share across projects…",
                 lambda: self._promote_to_shared(rule), True),
            )
        items.append(("-", lambda: None, True))
        if rule.get("scope") == "project" and rule.get("customized_from"):
            items.append((
                "Use shared version…",
                lambda: self._confirm_revert_to_shared(rule),
                bool(rule.get("definition")),
            ))
        else:
            items.append((
                self._delete_action_title(rule),
                lambda: self._confirm_delete_rule(rule),
                bool(rule.get("definition")),
            ))
        if rule.get("is_builtin") and not invalid:
            items.append((
                "Stop running everywhere",
                lambda: self._stop_rule_everywhere(rule),
                True,
            ))
        self.renderer.popup_menu(sender, items)

    @objc.python_method
    def _confirm_delete_rule(self, rule: dict[str, Any]) -> None:
        definition = rule.get("definition") or {}
        if not definition:
            self._set_banner("Reload this rule before deleting it.")
            return
        name = rule.get("name") or rule.get("title") or "rule"
        usage = int(rule.get("usage_count", 0) or 0)
        project_root = definition.get("project_root", "")
        source_path = definition.get("source_path", "")
        if definition.get("scope") == "project":
            effect = (
                f"This deletes only the definition owned by "
                f"{Path(project_root).name or project_root}. It will no longer "
                "run in that project."
            )
        else:
            effect = (
                f"This deletes the shared definition currently used by "
                f"{usage} project(s). Project-owned overrides remain, and "
                "assignment/hidden-finding choices are retained for this ID."
            )
        if rule.get("is_builtin"):
            effect = (
                "This removes the installed copy; the bundled template can be "
                "installed again. " + effect
            )
        editor_state = None
        if self._studio and hasattr(self._studio, "definition_state"):
            editor_state = self._studio.definition_state(definition)
            if editor_state["busy"]:
                self._set_banner(
                    "Wait for the open Rule Editor to finish saving or checking.")
                return
            if editor_state["dirty"]:
                effect += (
                    f" {editor_state['dirty']} open editor(s) have unsaved "
                    "changes; those changes will be discarded."
                )
        action = (
            "Remove rule" if rule.get("is_builtin") else "Delete rule")
        self.request_confirmation(
            f"{action} “{name}”?",
            effect + f"\n\nSource: {source_path}\n"
            "Open findings without a remaining rule move to Reviewed. "
            "Finding and audit history will be kept.",
            action,
            lambda state=editor_state: self._delete_rule(rule, state),
            destructive=True,
        )

    @objc.python_method
    def _delete_rule(
        self,
        rule: dict[str, Any],
        expected_editor_state: dict[str, int] | None = None,
    ) -> None:
        definition = dict(rule.get("definition") or {})
        if (
            expected_editor_state is not None
            and self._studio
            and self._studio.definition_state(definition)
            != expected_editor_state
        ):
            self._set_banner(
                "Open editors changed after confirmation. Review and try again.")
            return
        if self._studio and hasattr(
            self._studio, "set_definition_pending"
        ):
            self._studio.set_definition_pending(definition, True)

        def complete(result: dict[str, Any]) -> None:
            def apply() -> None:
                if not result.get("ok"):
                    if self._studio and hasattr(
                        self._studio, "set_definition_pending"
                    ):
                        self._studio.set_definition_pending(definition, False)
                    self._set_banner(
                        result.get("error", "Could not delete rule."))
                    return
                if self._studio and hasattr(
                    self._studio, "definition_removed"
                ):
                    self._studio.definition_removed(definition)
                warnings = [str(item) for item in result.get("warnings", [])]
                archived = int(result.get("archived_findings", 0) or 0)
                archive_copy = (
                    f" {archived} open finding"
                    f"{'s' if archived != 1 else ''} moved to Reviewed."
                    if archived else ""
                )
                self._set_banner(
                    "Rule definition removed." + archive_copy
                    + (
                        " Cleanup warning: " + "; ".join(warnings)
                        if warnings else ""
                    ))
                if self.route == "rules":
                    self._load_rules()
                else:
                    self.model.refresh()
            _on_main(apply)

        self.model.perform({
            "type": "delete_rule",
            "rule_id": rule.get("id"),
            "definition": definition,
        }, complete)

    @objc.python_method
    def _stop_rule_everywhere(self, rule: dict[str, Any]) -> None:
        self.model.perform({
            "type": "stop_rule_everywhere",
            "rule_id": rule.get("id"),
        }, lambda result: _on_main(lambda: (
            self._load_rules() if result.get("ok")
            else self._set_banner(
                result.get("error", "Could not stop rule everywhere."))
        )))

    @objc.python_method
    def _create_project_override(self, rule: dict[str, Any]) -> None:
        rule_id = rule.get("id", "")

        def loaded(result: dict[str, Any]) -> None:
            if not result.get("ok"):
                _on_main(lambda: self._set_banner(
                    result.get("error", "Global rule could not be read.")))
                return
            info = result["rule"]

            def saved(save_result: dict[str, Any]) -> None:
                def apply() -> None:
                    if save_result.get("ok"):
                        self._load_rules()
                        self.edit_rule({"id": rule_id})
                    else:
                        self._set_banner(
                            save_result.get("error", "Project override could not be created."))
                _on_main(apply)

            self.model.perform({
                "type": "save_rule",
                "rule_id": rule_id,
                "source": info.get("source", ""),
                "scope": "project",
                "project_root": self.selected_project,
            }, saved)

        self.model.perform({
            "type": "rule_get",
            "rule_id": rule_id,
            "project_root": self.selected_project,
        }, loaded)

    @objc.python_method
    def _confirm_revert_to_shared(self, rule: dict[str, Any]) -> None:
        definition = rule.get("definition") or {}
        if not definition:
            self._set_banner("Reload this rule before changing its source.")
            return
        name = rule.get("name") or rule.get("title") or "rule"
        source_path = definition.get("source_path", "")
        editor_warning = ""
        editor_state = None
        if self._studio and hasattr(self._studio, "definition_state"):
            editor_state = self._studio.definition_state(definition)
            if editor_state["busy"]:
                self._set_banner(
                    "Wait for the open Rule Editor to finish saving or checking.")
                return
            if editor_state["dirty"]:
                editor_warning = (
                    f" {editor_state['dirty']} open editor(s) have unsaved "
                    "changes; those changes will be discarded."
                )
        self.request_confirmation(
            f"Use the shared version of “{name}”?",
            "This removes only this project's customized source and keeps its "
            "current Run/Don't Run assignment. Existing finding and audit "
            f"history remains available.{editor_warning}"
            f"\n\nProject source: {source_path}",
            "Use Shared Version",
            lambda state=editor_state: self._revert_to_shared(rule, state),
            destructive=True,
        )

    @objc.python_method
    def _revert_to_shared(
        self,
        rule: dict[str, Any],
        expected_editor_state: dict[str, int] | None = None,
    ) -> None:
        definition = dict(rule.get("definition") or {})
        if (
            expected_editor_state is not None
            and self._studio
            and self._studio.definition_state(definition)
            != expected_editor_state
        ):
            self._set_banner(
                "Open editors changed after confirmation. Review and try again.")
            return
        if self._studio and hasattr(
            self._studio, "set_definition_pending"
        ):
            self._studio.set_definition_pending(definition, True)

        def complete(result: dict[str, Any]) -> None:
            def apply() -> None:
                if not result.get("ok"):
                    if self._studio and hasattr(
                        self._studio, "set_definition_pending"
                    ):
                        self._studio.set_definition_pending(definition, False)
                    self._set_banner(
                        result.get("error", "Could not use shared version."))
                    return
                if self._studio and hasattr(
                    self._studio, "definition_removed"
                ):
                    self._studio.definition_removed(definition)
                warnings = [str(item) for item in result.get("warnings", [])]
                self._set_banner(
                    "Project customization removed; assignment was preserved."
                    + (
                        " Cleanup warning: " + "; ".join(warnings)
                        if warnings else ""
                    ))
                self._load_rules()
            _on_main(apply)

        self.model.perform({
            "type": "revert_to_shared",
            "rule_id": rule.get("id"),
            "project_root": (
                definition.get("project_root") or self.selected_project),
            "definition": definition,
        }, complete)

    @objc.python_method
    def _promote_to_shared(self, rule: dict[str, Any]) -> None:
        project_root = self._rule_project_root(rule)
        self.model.perform({
            "type": "promote_to_shared",
            "rule_id": rule.get("id"),
            "project_root": project_root,
        }, lambda result: _on_main(lambda: (
            self._load_rules() if result.get("ok")
            else self._set_banner(result.get("error", "Could not share rule."))
        )))

    @objc.python_method
    def _test_rule_quick(self, rule: dict[str, Any]) -> None:
        rule_name = rule.get("name") or rule.get("title") or "rule"
        project_root = self._rule_project_root(rule)
        self._set_banner(f"Testing {rule_name}…")

        def complete(result: dict[str, Any]) -> None:
            if result.get("ok"):
                if result.get("total"):
                    message = (
                        f"{rule_name}: {result.get('passed')}/"
                        f"{result.get('total')} examples passed.")
                else:
                    message = result.get("note", "No examples to test.")
            else:
                message = result.get("error", "Test failed.")
            _on_main(lambda: self._set_banner(message))

        self.model.perform({
            "type": "test",
            "rule_id": rule.get("id"),
            "project_root": project_root,
        }, complete, timeout=180)

    @objc.python_method
    def edit_rule(self, rule: dict[str, Any]) -> None:
        rule_id = rule.get("id") or rule.get("rule_id")
        project_root = self._rule_project_root(rule)
        finding_context = rule.get("_finding_context")
        if not rule_id:
            return

        def complete(result: dict[str, Any]) -> None:
            def apply() -> None:
                if not result.get("ok"):
                    self._set_banner(result.get("error", "Rule could not be opened."))
                    return
                info = {**rule, **dict(result["rule"])}
                if finding_context:
                    info["_finding_context"] = finding_context
                self._open_rule_document(info, project_root)
            _on_main(apply)

        self.model.perform({
            "type": "rule_get",
            "rule_id": rule_id,
            "project_root": project_root,
        }, complete)

    @objc.python_method
    def _open_rule_document(
        self, rule: dict[str, Any], project_root: str
    ) -> None:
        from .rule_editor import RuleEditorManager
        rule = dict(rule)
        if rule.get("scope") == "builtin":
            rule["scope"] = "project"
            rule["path"] = ""
        if self._studio is None:
            self._studio = RuleEditorManager(
                self.model, self._rule_document_changed)
        self._studio.open(rule, project_root)

    @objc.python_method
    def _rule_document_changed(self, result: dict[str, Any]) -> None:
        warnings = [str(item) for item in result.get("warnings", [])]
        archived = int(result.get("archived_findings", 0) or 0)
        messages = []
        if archived:
            messages.append(
                f"{archived} open finding"
                f"{'s' if archived != 1 else ''} moved to Reviewed.")
        if warnings:
            messages.append("Cleanup warning: " + "; ".join(warnings))
        if messages:
            self._set_banner(" ".join(messages))
        if self.route == "rules":
            self._load_rules()
        else:
            self.model.refresh()

    @objc.python_method
    def show_add_rule_menu(self, sender) -> None:
        builtins = (self.rules_data or {}).get("builtins", [])
        items: list[tuple[str, Callable[[], None], bool]] = [
            ("New PAW rule", self._new_rule, True),
            ("New plain Python rule",
             lambda: self._new_rule(template="python"), True),
            ("Convert existing Cursor rules", self._convert_rules, True),
            ("-", lambda: None, True),
        ]
        items.extend([
            (f"Add built-in: {rule_id}",
             lambda rid=rule_id: self._add_builtin(rid), True)
            for rule_id in builtins
        ])
        self.renderer.popup_menu(sender, items)

    @objc.python_method
    def _new_rule(
        self, project_root: str | None = None, template: str = "paw"
    ) -> None:
        project_root = project_root or (
            self.selected_project if self.rules_context == "project" else "")
        if not project_root:
            self._set_banner("Choose a project before creating a rule.")
            return

        def complete(result: dict[str, Any]) -> None:
            def apply() -> None:
                if result.get("ok"):
                    self._open_rule_document(result["rule"], project_root)
                else:
                    self._set_banner(result.get("error", "Rule draft could not be created."))
            _on_main(apply)

        self.model.perform({
            "type": "new_rule_draft",
            "project_root": project_root,
            "template": template,
        }, complete)

    @objc.python_method
    def _convert_rules(self) -> None:
        self.model.perform({
            "type": "convert_rules",
            "scope": "project",
            "project_root": self.selected_project,
        }, lambda result: _on_main(lambda: (
            self._load_rules() if result.get("ok")
            else self._set_banner(result.get("error", "Rules could not be converted."))
        )))

    @objc.python_method
    def _add_builtin(self, rule_id: str, replace: bool = False) -> None:
        def complete(result: dict[str, Any]) -> None:
            def apply() -> None:
                if result.get("ok"):
                    self._load_rules()
                    self.edit_rule({"id": rule_id})
                elif result.get("conflict"):
                    self._set_banner(
                        "That rule already exists. Open it from the list; it was not overwritten.")
                else:
                    self._set_banner(result.get("error", "Built-in could not be added."))
            _on_main(apply)

        self.model.perform({
            "type": "add_builtin",
            "rule_id": rule_id,
            "scope": "project",
            "project_root": self.selected_project,
            "replace": replace,
        }, complete)

    # --- projects and global controls ----------------------------------
    @objc.python_method
    def toggle_project(self, project: dict[str, Any], enabled: bool) -> None:
        if not enabled:
            self.request_confirmation(
                f"Pause “{project.get('name') or Path(project.get('path', '')).name}”?",
                "No rules will evaluate new agent activity in this project until "
                "monitoring is resumed. Existing history is retained.",
                "Pause project",
                lambda: self._set_project_monitoring(project, False),
            )
            return
        self._set_project_monitoring(project, True)

    @objc.python_method
    def _set_project_monitoring(
        self, project: dict[str, Any], enabled: bool
    ) -> None:
        self.model.set_project_monitoring(
            project.get("path", ""), enabled,
            lambda result: _on_main(lambda: (
                self.model.refresh() if result.get("ok")
                else self._set_banner(result.get("error", "Project state could not be changed."))
            )),
        )

    @objc.python_method
    def show_project_menu(self, sender, project: dict[str, Any]) -> None:
        path = project.get("path", "")
        self.renderer.popup_menu(sender, [
            ("Manage rules", lambda: self.open_manage_rules(path), True),
            ("Warm rules now", lambda: self.model.perform(
                {"type": "warm", "project_root": path},
                lambda _result: self.model.refresh()), True),
            ("-", lambda: None, True),
            ("Open project", lambda: _open_path(path), True),
            ("Open rules folder", lambda: _open_path(
                str(config.project_rules_dir(path))), True),
            ("Open audit log", lambda: _open_path(
                str(config.project_log_file(path))), True),
            ("Copy project path", lambda: _copy_text(path), True),
        ])

    @objc.python_method
    def show_app_menu(self, sender) -> None:
        paused = bool(self.snapshot.daemon.get("monitoring_paused"))
        self.renderer.popup_menu(sender, [
            (
                "Resume monitoring" if paused else "Pause monitoring",
                lambda: self.toggle_pause(not paused),
                True,
            ),
            ("Open daemon log", lambda: _open_path(str(config.log_path())), True),
            ("Open tray log", lambda: _open_path(str(config.tray_log_path())), True),
            ("-", lambda: None, True),
            ("Quit Rules as Programs", self.quit, True),
        ])

    @objc.python_method
    def toggle_pause(self, paused: bool) -> None:
        if paused:
            self.request_confirmation(
                "Pause all monitoring?",
                "Every project will stop evaluating agent activity. The menu-bar "
                "item will remain visible so monitoring can be resumed.",
                "Pause all",
                lambda: self._set_global_pause(True),
            )
            return
        self._set_global_pause(False)

    @objc.python_method
    def _set_global_pause(self, paused: bool) -> None:
        self.model.perform(
            {"type": "set_monitoring_paused", "paused": paused},
            lambda result: _on_main(lambda: (
                self.model.refresh() if result.get("ok")
                else self._set_banner(result.get("error", "Monitoring state could not be changed."))
            )),
        )


def run_macos(*, demo: bool = False) -> int:
    global _CONTROLLER
    app = NSApplication.sharedApplication()
    controller = MacOSController.alloc().init()
    controller.demo = demo
    app.setDelegate_(controller)
    # Keep the delegate alive for the duration of NSApplication.run().
    _CONTROLLER = controller
    app.run()
    _CONTROLLER = None
    return 0
