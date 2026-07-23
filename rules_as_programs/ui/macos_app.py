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
    NSAppearanceNameAqua,
    NSAppearanceNameDarkAqua,
    NSImage,
    NSMinYEdge,
    NSPasteboard,
    NSPasteboardTypeString,
    NSPopover,
    NSPopoverBehaviorTransient,
    NSStatusBar,
    NSVariableStatusItemLength,
    NSViewController,
    NSWorkspace,
)
from Foundation import NSMakeSize, NSObject
from Foundation import NSData
from PyObjCTools import AppHelper

from .. import config
from .macos_views import POPOVER_HEIGHT, POPOVER_WIDTH, PopoverRenderer
from .model import UIModel, UISnapshot, demo_snapshot
from .status import StatusPresentation, status_presentation

_CONTROLLER = None
_PAW_ALPHA = None


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


def _dark_appearance() -> bool:
    appearance = NSApplication.sharedApplication().effectiveAppearance()
    match = appearance.bestMatchFromAppearancesWithNames_(
        [NSAppearanceNameAqua, NSAppearanceNameDarkAqua])
    return match == NSAppearanceNameDarkAqua


def _status_image(presentation: StatusPresentation) -> NSImage | None:
    """Draw an optically large paw with severity and attention satellites."""
    global _PAW_ALPHA
    try:
        from PIL import Image, ImageDraw, ImageFont
        if _PAW_ALPHA is None:
            source = Image.open(config.icon_png()).convert("RGBA")
            alpha = source.getchannel("A")
            bounds = alpha.getbbox()
            _PAW_ALPHA = alpha.crop(bounds) if bounds else alpha
        scale = 2
        has_primary = presentation.kind != "clear"
        extra_attention = presentation.attention_count > 0 and presentation.kind != "attention"
        width_pt = 22 + (8 if has_primary else 0) + (9 if extra_attention else 0)
        height_pt = 22
        canvas = Image.new("RGBA", (width_pt * scale, height_pt * scale), (0, 0, 0, 0))
        paw_alpha = _PAW_ALPHA.resize((21 * scale, 21 * scale), Image.Resampling.LANCZOS)
        paw_color = (245, 245, 245, 255) if _dark_appearance() else (25, 25, 25, 255)
        paw = Image.new("RGBA", paw_alpha.size, paw_color)
        paw.putalpha(paw_alpha)
        canvas.alpha_composite(paw, (0, 0))
        draw = ImageDraw.Draw(canvas)
        try:
            font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 8 * scale)
        except OSError:
            font = ImageFont.load_default()

        def circle(x: int, y: int, diameter: int, color, text: str, dark_text=False):
            box = tuple(value * scale for value in (x, y, x + diameter, y + diameter))
            draw.ellipse(box, fill=color)
            if text:
                fill = (25, 25, 25, 255) if dark_text else (255, 255, 255, 255)
                bbox = draw.textbbox((0, 0), text, font=font)
                tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
                tx = (x + diameter / 2) * scale - tw / 2
                ty = (y + diameter / 2) * scale - th / 2 - scale
                draw.text((tx, ty), text, font=font, fill=fill)

        if has_primary:
            colors = {
                "info": (35, 122, 230, 255),
                "warn": (255, 204, 0, 255),
                "high": (255, 149, 0, 255),
                "critical": (255, 59, 48, 255),
            }
            if presentation.kind == "attention":
                color = (175, 82, 222, 255)
            elif presentation.kind == "paused":
                color = (142, 142, 147, 255)
            elif presentation.kind == "unavailable":
                color = (255, 59, 48, 255)
            elif presentation.kind == "degraded":
                color = (255, 149, 0, 255)
            else:
                color = colors.get(presentation.severity or "info", colors["info"])
            circle(16, 8, 14, color, presentation.badge_text,
                   dark_text=presentation.severity == "warn")
        if extra_attention:
            circle(width_pt - 10, 1, 10, (175, 82, 222, 255), "?")

        buffer = io.BytesIO()
        canvas.save(buffer, format="PNG")
        raw = buffer.getvalue()
        data = NSData.dataWithBytes_length_(raw, len(raw))
        image = NSImage.alloc().initWithData_(data)
        image.setSize_(NSMakeSize(width_pt, height_pt))
        image.setTemplate_(False)
        return image
    except Exception:
        return None


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
    def _build_status_item(self) -> None:
        self.status_item = NSStatusBar.systemStatusBar().statusItemWithLength_(
            NSVariableStatusItemLength)
        button = self.status_item.button()
        image = _status_image(status_presentation(self.snapshot))
        if image:
            button.setImage_(image)
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
        self.popover.setContentSize_(NSMakeSize(POPOVER_WIDTH, POPOVER_HEIGHT))
        self.popover.setContentViewController_(self.content_controller)

    @objc.python_method
    def toggle_popover(self, sender) -> None:
        if self.popover.isShown():
            self.popover.performClose_(sender)
            return
        self._render()
        button = self.status_item.button()
        self.popover.showRelativeToRect_ofView_preferredEdge_(
            button.bounds(), button, NSMinYEdge)
        window = self.popover.contentViewController().view().window()
        if window:
            window.makeKeyWindow()

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
        image = _status_image(presentation)
        if image:
            button.setImage_(image)
            button.setTitle_("")
        else:
            button.setTitle_(presentation.badge_text or "RAP")
        button.setToolTip_(presentation.tooltip)
        button.setAccessibilityLabel_(presentation.accessibility)

    @objc.python_method
    def _render(self) -> None:
        if not self.content_controller:
            return
        self.content_view = self.renderer.render(self.snapshot)
        self.content_controller.setView_(self.content_view)

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
        callback: Callable[[], None],
    ) -> None:
        self.confirmation = {
            "title": title,
            "message": message,
            "confirm_title": confirm_title,
            "callback": callback,
        }
        self._render()

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
    def filter_rules(self, text: str) -> None:
        self.rules_filter = text
        self._render()

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
    def _snooze(self, group: dict[str, Any], seconds: float) -> None:
        self.model.snooze_rule(
            group.get("rule_id", ""),
            group.get("project_root", ""),
            seconds,
            lambda result: _on_main(lambda: self._set_banner(
                "Rule snoozed." if result.get("ok")
                else result.get("error", "Could not snooze rule."))),
        )

    @objc.python_method
    def _mute(self, group: dict[str, Any]) -> None:
        self.model.mute_rule(
            group.get("rule_id", ""),
            group.get("project_root", ""),
            lambda result: _on_main(lambda: self._set_banner(
                "Rule muted in this project. The current finding remains open."
                if result.get("ok") else result.get("error", "Could not mute rule."))),
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
            if group.get("suppressed"):
                items.append((
                    "Unmute rule for future findings",
                    lambda: self.model.perform({
                        "type": "unmute",
                        "rule_id": group.get("rule_id"),
                        "project_root": group.get("project_root"),
                    }, lambda result: _on_main(lambda: self._set_banner(
                        "Rule unmuted." if result.get("ok")
                        else result.get("error", "Could not unmute rule.")))),
                    True,
                ))
            else:
                items.append(("Reopen finding", lambda: self._reopen(group), True))
        else:
            items.extend([
                ("Mark Done", lambda: self.done_group(group), True),
                ("Snooze rule for 1 hour", lambda: self._snooze(group, 3600), True),
                ("Snooze rule until tomorrow", lambda: self._snooze(group, 24 * 3600), True),
                ("Mute rule in this project", lambda: self._mute(group), True),
                ("-", lambda: None, True),
                ("Done as false positive", lambda: self._review_with_reason(
                    group, "false_positive"), True),
                ("Done as acceptable risk", lambda: self._review_with_reason(
                    group, "acceptable_risk"), True),
            ])
        items.extend([
            ("-", lambda: None, True),
            ("Edit rule…", lambda: self.edit_rule({
                "id": group.get("rule_id"),
                "project_root": group.get("project_root"),
            }), True),
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
        self.selected_project = project_root
        self._load_rules()

    @objc.python_method
    def _load_rules(self) -> None:
        if not self.selected_project:
            self.rules_data = {}
            self._render()
            return
        self.rules_loading = True
        self._rules_request_token += 1
        token = self._rules_request_token
        requested_project = self.selected_project
        self._render()

        def complete(result: dict[str, Any]) -> None:
            def apply() -> None:
                if (
                    token != self._rules_request_token
                    or requested_project != self.selected_project
                ):
                    return
                self.rules_loading = False
                if result.get("ok"):
                    self.rules_data = result
                else:
                    self._set_banner(result.get("error", "Rules could not be loaded."))
                self._render()
            _on_main(apply)

        self.model.perform({
            "type": "rules",
            "project_root": requested_project,
        }, complete)

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
        self.model.perform({
            "type": "unmute",
            "rule_id": rule.get("id"),
            "project_root": self.selected_project,
        }, lambda result: _on_main(lambda: (
            self._load_rules() if result.get("ok")
            else self._set_banner(result.get("error", "Rule could not be unmuted."))
        )))

    @objc.python_method
    def show_rule_menu(self, sender, rule: dict[str, Any]) -> None:
        items = [
            (
                "Edit global rule…" if rule.get("scope") == "global"
                else "Edit in Rule Editor…",
                lambda: self.edit_rule(rule),
                True,
            ),
            ("Test rule", lambda: self._test_rule_quick(rule), True),
            (
                "Unmute in this project",
                lambda: self._unmute_rule(rule),
                bool(rule.get("muted")),
            ),
            ("Open Python file", lambda: _open_path(rule.get("source_path", "")), True),
            ("Copy Python path", lambda: _copy_text(rule.get("source_path", "")), True),
        ]
        if rule.get("scope") == "global" and self.selected_project:
            items.insert(
                1,
                ("Customize for this project…",
                 lambda: self._create_project_override(rule), True),
            )
        elif rule.get("scope") == "project" and rule.get("customized_from"):
            items.insert(
                1,
                ("Revert to Shared",
                 lambda: self._revert_to_shared(rule), True),
            )
        elif rule.get("scope") == "project":
            items.insert(
                1,
                ("Share across projects…",
                 lambda: self._promote_to_shared(rule), True),
            )
        self.renderer.popup_menu(sender, items)

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
    def _revert_to_shared(self, rule: dict[str, Any]) -> None:
        self.model.perform({
            "type": "revert_to_shared",
            "rule_id": rule.get("id"),
            "project_root": self.selected_project,
        }, lambda result: _on_main(lambda: (
            self._load_rules() if result.get("ok")
            else self._set_banner(result.get("error", "Could not revert rule."))
        )))

    @objc.python_method
    def _promote_to_shared(self, rule: dict[str, Any]) -> None:
        self.model.perform({
            "type": "promote_to_shared",
            "rule_id": rule.get("id"),
            "project_root": self.selected_project,
        }, lambda result: _on_main(lambda: (
            self._load_rules() if result.get("ok")
            else self._set_banner(result.get("error", "Could not share rule."))
        )))

    @objc.python_method
    def _test_rule_quick(self, rule: dict[str, Any]) -> None:
        self._set_banner(f"Testing {rule.get('id')}…")

        def complete(result: dict[str, Any]) -> None:
            if result.get("ok"):
                if result.get("total"):
                    message = (
                        f"{rule.get('id')}: {result.get('passed')}/"
                        f"{result.get('total')} examples passed.")
                else:
                    message = result.get("note", "No examples to test.")
            else:
                message = result.get("error", "Test failed.")
            _on_main(lambda: self._set_banner(message))

        self.model.perform({
            "type": "test",
            "rule_id": rule.get("id"),
            "project_root": self.selected_project,
        }, complete, timeout=180)

    @objc.python_method
    def edit_rule(self, rule: dict[str, Any]) -> None:
        rule_id = rule.get("id") or rule.get("rule_id")
        project_root = rule.get("project_root") or self.selected_project
        finding_context = rule.get("_finding_context")
        if not rule_id:
            return

        def complete(result: dict[str, Any]) -> None:
            def apply() -> None:
                if not result.get("ok"):
                    self._set_banner(result.get("error", "Rule could not be opened."))
                    return
                info = dict(result["rule"])
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
            self._studio = RuleEditorManager(self.model)
        self._studio.open(rule, project_root)

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
        project_root = project_root or self.selected_project
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
            ("Manage rules", lambda: (
                setattr(self, "selected_project", path),
                self.select_tab("rules"),
            ), True),
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
