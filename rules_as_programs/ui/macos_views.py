"""Native AppKit views for the menu-bar findings inbox.

The renderer uses ordinary AppKit controls rather than embedding HTML or
flattening data into a text view.  It is intentionally state-light: the owning
controller supplies snapshots and handles every action, while this class owns
only the current native controls and their callback targets.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from AppKit import (
    NSBox,
    NSBoxSeparator,
    NSButton,
    NSColor,
    NSControlStateValueOff,
    NSControlStateValueOn,
    NSFont,
    NSLineBreakByTruncatingTail,
    NSMenu,
    NSMenuItem,
    NSPopUpButton,
    NSProgressIndicator,
    NSProgressIndicatorStyleSpinning,
    NSSearchField,
    NSSegmentSwitchTrackingSelectOne,
    NSScrollView,
    NSSegmentedControl,
    NSSwitchButton,
    NSTextField,
    NSView,
    NSViewHeightSizable,
    NSViewWidthSizable,
)
from Foundation import NSMakeRect, NSObject

from .macos_controls import (
    RAPHoverButton,
    RAPInteractiveRow,
    ButtonRole,
    style_button,
)
from .model import UISnapshot
from .layout import (
    FOOTER_HEIGHT,
    POPOVER_MAX_HEIGHT as POPOVER_HEIGHT,
    POPOVER_WIDTH,
    PopoverLayout,
    fit_popover_layout,
)

PAD = 14
HEADER_HEIGHT = 92
CONTENT_TOP = HEADER_HEIGHT
CONTENT_HEIGHT = POPOVER_HEIGHT - HEADER_HEIGHT - FOOTER_HEIGHT

SEVERITY_RANK = {"critical": 3, "warn": 2, "info": 1}
SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "warn": "WARNING",
    "info": "INFO",
}


class RAPFlippedView(NSView):
    def isFlipped(self):
        return True


class RAPPopoverActionTarget(NSObject):
    def invoke_(self, sender):
        callback = getattr(self, "_callbacks", {}).get(int(sender.tag()))
        if callback:
            callback(sender)


class RAPPopoverMenuActionTarget(NSObject):
    def invoke_(self, sender):
        callbacks = getattr(self, "_callbacks", {})
        callback = callbacks.pop(int(sender.tag()), None)
        owner = getattr(self, "owner", None)
        if callback and owner:
            owner.defer_menu_action(callback)


def _relative_time(ts: float) -> str:
    delta = max(0, int(time.time() - float(ts or 0)))
    if delta < 60:
        return "now" if delta < 5 else f"{delta}s"
    if delta < 3600:
        return f"{delta // 60}m"
    if delta < 86400:
        return f"{delta // 3600}h"
    return f"{delta // 86400}d"


def _project_name(path: str) -> str:
    return Path(path).name or path or "Unknown project"


class PopoverRenderer:
    """Rebuilds a small native hierarchy from one immutable snapshot."""

    def __init__(self, controller: Any) -> None:
        self.controller = controller
        self._callbacks: dict[int, Callable[[Any], None]] = {}
        self._target = RAPPopoverActionTarget.alloc().init()
        self._target._callbacks = self._callbacks
        self._next_tag = 1
        self._menu_callbacks: dict[int, Callable[[], None]] = {}
        self._menu_target = RAPPopoverMenuActionTarget.alloc().init()
        self._menu_target._callbacks = self._menu_callbacks
        self._menu_target.owner = controller
        self._next_menu_tag = 1
        self._menus: list[NSMenu] = []
        self.layout = PopoverLayout(
            POPOVER_WIDTH, POPOVER_HEIGHT, HEADER_HEIGHT, FOOTER_HEIGHT)

    def _reset(self) -> None:
        self._callbacks.clear()
        self._next_tag = 1
        self._menus.clear()

    def _wire(self, control: Any, callback: Callable[[Any], None]) -> Any:
        tag = self._next_tag
        self._next_tag += 1
        self._callbacks[tag] = callback
        control.setTag_(tag)
        control.setTarget_(self._target)
        control.setAction_("invoke:")
        return control

    def _wire_menu(
        self, item: NSMenuItem, callback: Callable[[], None]
    ) -> int:
        tag = self._next_menu_tag
        self._next_menu_tag += 1
        self._menu_callbacks[tag] = callback
        item.setTag_(tag)
        item.setTarget_(self._menu_target)
        item.setAction_("invoke:")
        return tag

    @staticmethod
    def _label(
        text: str,
        frame: tuple[float, float, float, float],
        *,
        size: float = 12,
        bold: bool = False,
        color: Any | None = None,
        lines: int = 1,
        monospace: bool = False,
    ) -> NSTextField:
        label = NSTextField.labelWithString_(str(text))
        label.setFrame_(NSMakeRect(*frame))
        if monospace:
            font = NSFont.userFixedPitchFontOfSize_(size)
        elif bold:
            font = NSFont.boldSystemFontOfSize_(size)
        else:
            font = NSFont.systemFontOfSize_(size)
        if font:
            label.setFont_(font)
        label.setTextColor_(color or NSColor.labelColor())
        label.setMaximumNumberOfLines_(lines)
        label.setLineBreakMode_(NSLineBreakByTruncatingTail)
        if lines > 1:
            label.cell().setWraps_(True)
            label.cell().setScrollable_(False)
        return label

    def _button(
        self,
        title: str,
        frame: tuple[float, float, float, float],
        callback: Callable[[Any], None],
        *,
        bordered: bool = True,
        accessibility: str | None = None,
        tooltip: str | None = None,
        role: ButtonRole | None = None,
    ) -> NSButton:
        resolved_role = role or ("secondary" if bordered else "flat")
        button_class = (
            RAPHoverButton
            if resolved_role in ("flat", "icon")
            else NSButton
        )
        button = button_class.alloc().initWithFrame_(NSMakeRect(*frame))
        button.setTitle_(title)
        style_button(
            button,
            role=resolved_role,
            accessibility=accessibility,
            tooltip=tooltip,
        )
        return self._wire(button, callback)

    def _row_button(
        self,
        frame: tuple[float, float, float, float],
        callback: Callable[[Any], None],
        *,
        accessibility: str,
        tooltip: str | None = None,
    ) -> RAPInteractiveRow:
        button = RAPInteractiveRow.alloc().initWithFrame_(NSMakeRect(*frame))
        button.setAccessibilityLabel_(accessibility)
        button.setToolTip_(tooltip or accessibility)
        return self._wire(button, callback)

    @staticmethod
    def _separator(parent: NSView, y: float, x: float = PAD,
                   width: float = POPOVER_WIDTH - 2 * PAD) -> None:
        separator = NSBox.alloc().initWithFrame_(NSMakeRect(x, y, width, 1))
        separator.setBoxType_(NSBoxSeparator)
        parent.addSubview_(separator)

    def _scroll(self, frame: tuple[float, float, float, float],
                content_height: float) -> tuple[NSScrollView, RAPFlippedView]:
        scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(*frame))
        scroll.setHasVerticalScroller_(True)
        scroll.setDrawsBackground_(False)
        scroll.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)
        height = max(frame[3], content_height)
        document = RAPFlippedView.alloc().initWithFrame_(
            NSMakeRect(0, 0, frame[2], height))
        document.setAutoresizingMask_(NSViewWidthSizable)
        scroll.setDocumentView_(document)
        return scroll, document

    def _measure_content(self, snapshot: UISnapshot, route: str) -> float:
        if getattr(self.controller, "confirmation", None):
            return 360
        if route == "finding":
            return 460
        if route == "rules":
            data = getattr(self.controller, "rules_data", {}) or {}
            rules = data.get("rules") or []
            errors = data.get("errors") or []
            return 100 + max(80, (len(errors) + len(rules)) * 76)
        if route == "projects":
            return max(90, len(snapshot.projects) * 86 + 12)
        mode = getattr(self.controller, "inbox_mode", "open")
        if snapshot.status in ("loading", "unavailable"):
            return 150
        groups = (
            getattr(self.controller, "history_groups", [])
            if mode == "history"
            else [
                group
                for rows in snapshot.findings_by_project.values()
                for group in rows
            ]
        )
        current = sum(1 for group in groups if not group.get("stale"))
        stale = sum(1 for group in groups if group.get("stale"))
        projects = len({
            group.get("project_root") for group in groups if not group.get("stale")
        })
        attention = len(snapshot.attention) if mode == "open" else 0
        if not (current or stale or attention):
            return 140
        return (
            38
            + (30 + attention * 70 if attention else 0)
            + (30 + stale * 40 if stale else 0)
            + projects * 30
            + current * 40
        )

    def render(
        self, snapshot: UISnapshot, max_height: float = POPOVER_HEIGHT
    ) -> tuple[NSView, tuple[float, float]]:
        self._reset()
        route = getattr(self.controller, "route", "inbox")
        health, _color = self._health_copy(snapshot)
        self.layout = fit_popover_layout(
            self._measure_content(snapshot, route),
            show_status=bool(health),
            max_height=max_height,
        )
        root = RAPFlippedView.alloc().initWithFrame_(
            NSMakeRect(0, 0, self.layout.width, self.layout.height))
        root.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)
        confirmation = getattr(self.controller, "confirmation", None)
        if confirmation:
            self._render_confirmation(root, confirmation)
            return root, (self.layout.width, self.layout.height)
        self._render_header(root, snapshot)
        if route == "rules":
            self._render_rules(root, snapshot)
        elif route == "projects":
            self._render_projects(root, snapshot)
        else:
            self._render_inbox(root, snapshot)
        self._render_footer(root, snapshot)
        return root, (self.layout.width, self.layout.height)

    def _render_confirmation(self, root: NSView, confirmation: dict[str, Any]) -> None:
        root.addSubview_(self._label(
            "Confirm change", (PAD, 16, 300, 24), size=16, bold=True))
        self._separator(root, 50, 0, POPOVER_WIDTH)
        root.addSubview_(self._label(
            confirmation.get("title", "Stop monitoring?"),
            (PAD + 18, 72, POPOVER_WIDTH - 2 * PAD - 36, 44),
            size=15, bold=True, lines=2))
        button_y = self.layout.height - 48
        root.addSubview_(self._label(
            confirmation.get("message", ""),
            (
                PAD + 18,
                122,
                POPOVER_WIDTH - 2 * PAD - 36,
                max(120, button_y - 138),
            ),
            size=11, lines=14, color=NSColor.secondaryLabelColor()))
        root.addSubview_(self._button(
            "Cancel", (222, button_y, 88, 32),
            lambda _sender: self.controller.cancel_confirmation()))
        root.addSubview_(self._button(
            confirmation.get("confirm_title", "Confirm"),
            (318, button_y, 96, 32),
            lambda _sender: self.controller.confirm_change(),
            role=(
                "destructive"
                if confirmation.get("destructive") else "primary"
            )))

    # --- shared chrome --------------------------------------------------
    def _health_copy(self, snapshot: UISnapshot) -> tuple[str, Any]:
        banner = str(getattr(self.controller, "banner", "") or "")
        if banner:
            return banner, NSColor.systemBlueColor()
        if snapshot.status == "loading":
            return "Connecting…", NSColor.secondaryLabelColor()
        if snapshot.status == "unavailable":
            return "Daemon unavailable", NSColor.systemRedColor()
        health = snapshot.daemon.get("health", "ready")
        if health == "warming":
            return "Preparing local rules…", NSColor.systemOrangeColor()
        if health == "degraded":
            return "Some rules need attention", NSColor.systemOrangeColor()
        if health == "paused":
            return "Monitoring paused", NSColor.secondaryLabelColor()
        return "", NSColor.secondaryLabelColor()

    def _render_header(self, root: NSView, snapshot: UISnapshot) -> None:
        health, color = self._health_copy(snapshot)
        controls_y = 58 if health else 36
        root.addSubview_(self._label(
            "Rules as Programs",
            (PAD, 12 if health else 8, 240, 24), size=16, bold=True))
        if health:
            root.addSubview_(self._label(
                health, (PAD, 36, 330, 18), size=11, color=color))
        if snapshot.daemon.get("health") == "warming":
            spinner = NSProgressIndicator.alloc().initWithFrame_(
                NSMakeRect(390, 20, 18, 18))
            spinner.setStyle_(NSProgressIndicatorStyleSpinning)
            spinner.setIndeterminate_(True)
            spinner.startAnimation_(None)
            root.addSubview_(spinner)
        route = getattr(self.controller, "route", "inbox")
        if route == "inbox":
            projects = snapshot.projects
            choices = [{"path": "", "name": "All Projects"}, *projects]
            popup = NSPopUpButton.alloc().initWithFrame_pullsDown_(
                NSMakeRect(PAD, controls_y, 292, 27), False)
            popup.removeAllItems()
            for project in choices:
                popup.addItemWithTitle_(project.get("name") or _project_name(
                    project.get("path", "")))
            selected_path = getattr(self.controller, "home_project", "")
            selected_index = next(
                (index for index, project in enumerate(choices)
                 if project.get("path", "") == selected_path), 0)
            popup.selectItemAtIndex_(selected_index)
            self._wire(popup, lambda sender: self.controller.select_home_project(
                choices[sender.indexOfSelectedItem()].get("path", "")))
            root.addSubview_(popup)
            root.addSubview_(self._button(
                "+ Rule", (316, controls_y - 1, 98, 29),
                lambda sender: self.controller.begin_add_rule(
                    getattr(self.controller, "home_project", ""), sender),
                role="primary"))
        else:
            root.addSubview_(self._button(
                "‹ Findings", (PAD, controls_y - 1, 88, 28),
                lambda _sender: self.controller.select_tab("inbox"),
                bordered=False))
            library = getattr(
                self.controller, "rules_context", "library") == "library"
            title = (
                (
                    f"Rules for {_project_name(getattr(self.controller, 'selected_project', ''))}"
                    if not library
                    else "Rule Library"
                )
                if route == "rules" else "Projects"
            )
            root.addSubview_(self._label(
                title, (112, controls_y + 3, 250, 20), size=12, bold=True))
        self._separator(
            root, self.layout.header_height - 1, 0, self.layout.width)

    def _render_footer(self, root: NSView, snapshot: UISnapshot) -> None:
        y = self.layout.height - self.layout.footer_height
        self._separator(root, y, 0, POPOVER_WIDTH)
        routes = ("inbox", "rules", "projects")
        navigation = NSSegmentedControl.alloc().initWithFrame_(
            NSMakeRect(PAD, y + 7, 250, 27))
        navigation.setSegmentCount_(len(routes))
        navigation.setTrackingMode_(NSSegmentSwitchTrackingSelectOne)
        for index, title in enumerate(("Findings", "Rules", "Projects")):
            navigation.setLabel_forSegment_(title, index)
        current = getattr(self.controller, "route", "inbox")
        navigation.setSelectedSegment_(
            routes.index(current) if current in routes else 0)

        def select_route(sender) -> None:
            selected = int(sender.selectedSegment())
            if selected == 1:
                self.controller.open_rule_library()
            else:
                self.controller.select_tab(routes[selected])

        self._wire(navigation, select_route)
        root.addSubview_(navigation)
        root.addSubview_(self._button(
            "More…", (346, y + 7, 68, 27),
            lambda sender: self.controller.show_app_menu(sender),
            bordered=False,
        ))

    # --- Inbox ----------------------------------------------------------
    def _inbox_groups(self, snapshot: UISnapshot) -> dict[str, list[dict[str, Any]]]:
        if getattr(self.controller, "inbox_mode", "open") == "history":
            groups = getattr(self.controller, "history_groups", [])
            out: dict[str, list[dict[str, Any]]] = {}
            for group in groups or []:
                out.setdefault(group.get("project_root", ""), []).append(group)
            source = out
        else:
            source = snapshot.findings_by_project
        selected = getattr(self.controller, "home_project", "")
        if selected:
            return {selected: source.get(selected, [])} if source.get(selected) else {}
        return source

    def _render_inbox(self, root: NSView, snapshot: UISnapshot) -> None:
        mode = getattr(self.controller, "inbox_mode", "open")
        content_top = self.layout.header_height
        content_height = (
            self.layout.height - self.layout.header_height
            - self.layout.footer_height
        )
        mode_control = NSSegmentedControl.alloc().initWithFrame_(
            NSMakeRect(PAD, content_top + 6, 220, 24))
        mode_control.setSegmentCount_(2)
        mode_control.setLabel_forSegment_("Needs Review", 0)
        mode_control.setLabel_forSegment_("Reviewed", 1)
        mode_control.setSelectedSegment_(0 if mode == "open" else 1)
        self._wire(mode_control, lambda sender: self.controller.set_inbox_mode(
            "open" if sender.selectedSegment() == 0 else "history"))
        root.addSubview_(mode_control)

        if snapshot.status == "unavailable":
            self._render_message_state(
                root, "Rules cannot be checked",
                snapshot.error or "The local daemon is unavailable.",
                "Retry", self.controller.retry)
            return
        if mode == "history" and getattr(self.controller, "history_loading", False):
            self._render_loading(root, "Loading review history…")
            return

        by_project = self._inbox_groups(snapshot)
        stale_groups = [
            group for groups in by_project.values() for group in groups
            if group.get("stale")
        ]
        by_project = {
            project: [group for group in groups if not group.get("stale")]
            for project, groups in by_project.items()
            if any(not group.get("stale") for group in groups)
        }
        attention = list(snapshot.attention) if mode == "open" else []
        selected_project = getattr(self.controller, "home_project", "")
        if selected_project:
            attention = [
                item for item in attention
                if item.get("project_root") == selected_project
            ]
        ordered: list[tuple[str, list[dict[str, Any]]]] = []
        for project, groups in by_project.items():
            sorted_groups = sorted(
                groups,
                key=lambda group: (
                    SEVERITY_RANK.get(group.get("severity", "info"), 0),
                    float(group.get("last_seen") or group.get("ts", 0)),
                ),
                reverse=True,
            )
            ordered.append((project, sorted_groups))
        ordered.sort(
            key=lambda item: max(
                (SEVERITY_RANK.get(g.get("severity", "info"), 0) * 10**12
                 + float(g.get("last_seen") or g.get("ts", 0))
                 for g in item[1]),
                default=0,
            ),
            reverse=True,
        )

        if not ordered and not attention and not stale_groups:
            if mode == "history":
                self._render_message_state(
                    root, "No reviewed findings yet",
                    "Findings you mark Done or suppress will remain available here.")
            elif snapshot.status == "loading":
                self._render_loading(root, "Checking monitored projects…")
            else:
                projects = snapshot.projects
                selected = getattr(self.controller, "home_project", "")
                if selected:
                    projects = [
                        project for project in projects
                        if project.get("path") == selected
                    ]
                if not projects:
                    self._render_message_state(
                        root, "Set up your first project",
                        "Run “rap init --scan” in a Cursor project to begin auditing.")
                elif all(project.get("status") == "setup_needed" for project in projects):
                    self._render_message_state(
                        root, "Cursor setup is incomplete",
                        "Install hooks and rules, then reload Cursor.",
                        "View projects", lambda: self.controller.select_tab("projects"))
                else:
                    self._render_message_state(
                        root,
                        "All reviewed",
                        "",
                        "+ Rule",
                        lambda: self.controller.begin_add_rule(
                            getattr(self.controller, "home_project", "")),
                    )
            return

        row_height = 40
        total_height = (
            10
            + (30 + len(attention) * 70 if attention else 0)
            + (30 + len(stale_groups) * 40 if stale_groups else 0)
            + sum(30 + len(groups) * row_height for _, groups in ordered)
        )
        scroll, document = self._scroll(
            (0, content_top + 34, self.layout.width,
             max(40, content_height - 34)), total_height)
        root.addSubview_(scroll)
        y = 8
        if attention:
            document.addSubview_(self._label(
                "Needs reply", (PAD, y + 3, 180, 22),
                size=12, bold=True, color=NSColor.systemPurpleColor()))
            document.addSubview_(self._label(
                f"{len(attention)}", (194, y + 3, 28, 20),
                size=11, color=NSColor.secondaryLabelColor()))
            y += 30
            for item in attention:
                project = _project_name(item.get("project_root", ""))
                message = str(item.get("message", "")).strip().replace("\n", " ")
                document.addSubview_(self._label(
                    "?", (PAD, y + 10, 24, 24), size=16, bold=True,
                    color=NSColor.systemPurpleColor()))
                document.addSubview_(self._label(
                    project, (48, y + 7, 220, 20), size=12, bold=True))
                document.addSubview_(self._label(
                    _relative_time(item.get("created_at", 0)),
                    (274, y + 8, 42, 18), size=10,
                    color=NSColor.secondaryLabelColor()))
                document.addSubview_(self._label(
                    message, (48, y + 29, 270, 32), size=10.5, lines=2,
                    color=NSColor.secondaryLabelColor()))
                document.addSubview_(self._button(
                    "Open Cursor", (322, y + 7, 98, 25),
                    lambda _sender, value=item: self.controller.open_attention_project(value),
                    bordered=False))
                document.addSubview_(self._button(
                    "Not waiting", (340, y + 34, 84, 25),
                    lambda _sender, value=item: self.controller.dismiss_attention(value),
                    bordered=False))
                self._separator(document, y + 68, 48, POPOVER_WIDTH - 62)
                y += 70
        if stale_groups:
            document.addSubview_(self._label(
                "Rule changed — needs recheck",
                (PAD, y + 3, 250, 22), size=12, bold=True,
                color=NSColor.secondaryLabelColor()))
            y += 30
            for group in stale_groups:
                self._render_finding_row(document, y, group, "stale")
                y += 40
        for project, groups in ordered:
            document.addSubview_(self._label(
                _project_name(project),
                (PAD, y + 3, 178, 22), size=12, bold=True))
            document.addSubview_(self._label(
                f"{len(groups)}", (194, y + 3, 28, 20),
                size=11, color=NSColor.secondaryLabelColor()))
            document.addSubview_(self._button(
                "+ Rule", (224, y, 58, 25),
                lambda sender, path=project: self.controller.begin_add_rule(path, sender),
                bordered=False))
            document.addSubview_(self._button(
                "Rules", (284, y, 52, 25),
                lambda _sender, path=project: self.controller.open_manage_rules(path),
                bordered=False))
            if mode == "open":
                document.addSubview_(self._button(
                    "✓ All", (350, y, 64, 25),
                    lambda _sender, path=project: self.controller.done_project(path),
                    bordered=False,
                    accessibility=f"Mark all findings in {_project_name(project)} reviewed",
                ))
            y += 30
            for group in groups:
                self._render_finding_row(document, y, group, mode)
                y += row_height

    def _render_finding_row(
        self, parent: NSView, y: float, group: dict[str, Any], mode: str
    ) -> None:
        severity = group.get("severity", "info")
        color = {
            "critical": NSColor.systemRedColor(),
            "warn": NSColor.systemYellowColor(),
            "info": NSColor.systemBlueColor(),
        }.get(severity, NSColor.secondaryLabelColor())
        parent.addSubview_(self._label(
            SEVERITY_LABEL.get(severity, severity.upper()),
            (PAD, y + 11, 66, 16), size=9, bold=True, color=color))
        title = group.get("rule_title") or group.get("rule_id", "Rule")
        if mode == "stale":
            title = f"{title} · rule changed"
        parent.addSubview_(self._label(
            title, (82, y + 7, 225, 22), size=12, bold=True))
        age = _relative_time(group.get("last_seen") or group.get("ts", 0))
        parent.addSubview_(self._label(
            age, (309, y + 9, 38, 18), size=10,
            color=NSColor.secondaryLabelColor()))
        occurrences = int(group.get("occurrences", 1) or 1)
        if occurrences > 1:
            parent.addSubview_(self._label(
                f"×{occurrences}", (274, y + 9, 30, 18), size=10,
                color=NSColor.secondaryLabelColor()))
        parent.addSubview_(self._row_button(
            (8, y + 2, 340, 35),
            lambda _sender, value=group: self.controller.open_finding(value),
            accessibility=f"Open finding: {title}",
        ))
        if mode == "open":
            parent.addSubview_(self._button(
                "✓", (352, y + 6, 28, 28),
                lambda _sender, value=group: self.controller.done_group(value),
                bordered=False,
                accessibility=f"Mark {title} reviewed",
                role="icon",
            ))
        parent.addSubview_(self._button(
            "•••", (390, y + 6, 32, 28),
            lambda sender, value=group: self.controller.show_finding_menu(sender, value),
            bordered=False,
            accessibility=f"More actions for {title}",
            role="icon",
        ))
        self._separator(parent, y + 39, 82, POPOVER_WIDTH - 96)

    # --- Finding detail -------------------------------------------------
    def _render_detail_shell(self, root: NSView, snapshot: UISnapshot) -> None:
        root.addSubview_(self._button(
            "‹ Inbox", (PAD, 10, 82, 28),
            lambda _sender: self.controller.close_finding(),
            bordered=False,
        ))
        group = getattr(self.controller, "selected_finding", {}) or {}
        title = group.get("rule_title") or group.get("rule_id", "Finding")
        root.addSubview_(self._label(
            title, (104, 12, 300, 24), size=15, bold=True))
        self._separator(root, 45, 0, POPOVER_WIDTH)
        if getattr(self.controller, "detail_loading", False):
            self._render_loading(root, "Loading exact evidence…", top=60)
            return
        error = getattr(self.controller, "detail_error", "")
        if error:
            self._render_message_state(
                root, "Evidence unavailable", error, "Retry",
                lambda: self.controller.open_finding(group), top=58)
            return
        detail = getattr(self.controller, "finding_detail", {}) or {}
        self._render_finding_detail(root, group, detail)

    def _render_finding_detail(
        self, root: NSView, group: dict[str, Any], detail: dict[str, Any]
    ) -> None:
        finding = detail.get("finding") or group
        trace = detail.get("trace") or []
        evidence = next((item for item in trace if item.get("type") == "evidence"), {})
        paw = next((item for item in reversed(trace) if item.get("type") == "paw"), {})
        events = evidence.get("events") or []
        probes = evidence.get("probes") or []
        occurrences = detail.get("occurrences") or []
        show_raw = bool(getattr(self.controller, "show_raw_trace", False))

        sections: list[tuple[str, str, bool]] = []
        project = _project_name(finding.get("project_root", ""))
        metadata = (
            f"{SEVERITY_LABEL.get(finding.get('severity', 'info'), 'INFO')}  ·  "
            f"{project}  ·  {_relative_time(finding.get('ts', 0))} ago"
        )
        sections.append(("What was flagged", str(finding.get("message", "")), False))
        sections.append(("Project", str(finding.get("project_root", "")), True))
        decision = str(paw.get("output") or finding.get("label") or "Deterministic rule")
        sections.append(("Rule decision", decision, True))
        if probes:
            probe_text = "\n\n".join(
                f"$ {probe.get('command', '')}\n{probe.get('output') or '(no output)'}"
                for probe in probes)
            sections.append(("Checks performed", probe_text, True))
        if events:
            event_text = "\n\n".join(
                f"{event.get('kind', 'event')} · {_relative_time(event.get('ts', 0))} ago\n"
                f"{event.get('text', '')}"
                for event in events[-12:])
            sections.append(("Agent activity", event_text, False))
        elif evidence.get("text"):
            sections.append(("Evidence observed", str(evidence.get("text")), True))
        if occurrences:
            first = min(float(item.get("ts", 0)) for item in occurrences)
            last = max(float(item.get("ts", 0)) for item in occurrences)
            sections.append((
                "Occurrence history",
                f"{len(occurrences)} occurrence{'s' if len(occurrences) != 1 else ''} · "
                f"first {_relative_time(first)} ago · latest {_relative_time(last)} ago",
                False,
            ))
        if show_raw:
            sections.append(("Raw trace", json.dumps(trace, indent=2, ensure_ascii=False), True))

        estimated = 80
        for _title, body, _mono in sections:
            estimated += 50 + min(230, max(36, (body.count("\n") + len(body) // 70 + 1) * 16))
        scroll, document = self._scroll(
            (0, 46, POPOVER_WIDTH, POPOVER_HEIGHT - 46 - 58), estimated)
        root.addSubview_(scroll)
        y = 14
        document.addSubview_(self._label(
            metadata, (PAD, y, 390, 18), size=10,
            color=NSColor.secondaryLabelColor()))
        y += 30
        for heading, body, monospace in sections:
            document.addSubview_(self._label(
                heading, (PAD, y, 390, 20), size=12, bold=True))
            y += 24
            line_count = body.count("\n") + len(body) // 70 + 1
            height = min(230, max(36, line_count * 16))
            document.addSubview_(self._label(
                body, (PAD, y, 398, height), size=10.5, lines=max(2, int(height // 16)),
                monospace=monospace,
                color=NSColor.secondaryLabelColor() if not monospace else NSColor.labelColor()))
            y += height + 22
            self._separator(document, y - 10)
        document.addSubview_(self._button(
            "Hide raw trace" if show_raw else "Show raw trace",
            (PAD, y, 115, 26),
            lambda _sender: self.controller.toggle_raw_trace(),
            bordered=False,
        ))

        bar_y = POPOVER_HEIGHT - 58
        self._separator(root, bar_y, 0, POPOVER_WIDTH)
        root.addSubview_(self._label(
            "Done hides this occurrence; future findings can reappear.",
            (PAD, bar_y + 8, 244, 36), size=9,
            color=NSColor.secondaryLabelColor(), lines=2))
        root.addSubview_(self._button(
            "More", (268, bar_y + 14, 66, 30),
            lambda sender: self.controller.show_finding_menu(sender, group)))
        root.addSubview_(self._button(
            "Done", (340, bar_y + 14, 74, 30),
            lambda _sender: self.controller.done_group(group)))

    # --- Rules ----------------------------------------------------------
    def _render_rules(self, root: NSView, snapshot: UISnapshot) -> None:
        content_top = self.layout.header_height
        content_height = (
            self.layout.height - self.layout.header_height
            - self.layout.footer_height
        )
        projects = snapshot.projects
        library = getattr(
            self.controller, "rules_context", "library") == "library"
        selected = (
            "" if library
            else getattr(self.controller, "selected_project", ""))
        choices = [{"path": "", "name": "All Rules"}, *projects]
        popup = NSPopUpButton.alloc().initWithFrame_pullsDown_(
            NSMakeRect(PAD, content_top + 6, 230, 26), False)
        popup.removeAllItems()
        for project in choices:
            popup.addItemWithTitle_(project.get("name") or _project_name(project.get("path", "")))
        selected_index = next(
            (index for index, project in enumerate(choices)
             if project.get("path") == selected), 0)
        if choices:
            popup.selectItemAtIndex_(selected_index)
        self._wire(popup, lambda sender: self.controller.select_project(
            choices[sender.indexOfSelectedItem()].get("path", "")) if choices else None)
        root.addSubview_(popup)
        root.addSubview_(self._button(
            "+ Add Rule", (326, content_top + 5, 88, 28),
            lambda sender: (
                self.controller.show_add_rule_menu(sender)
                if not library else self.controller.begin_add_rule("", sender)
            ),
            role="primary"))
        root.addSubview_(self._label(
            (
                "Choose which rules run in this project."
                if not library else "All rule definitions."
            ),
            (PAD, content_top + 37, 300, 18), size=10,
            color=NSColor.secondaryLabelColor()))
        search = NSSearchField.alloc().initWithFrame_(
            NSMakeRect(PAD, content_top + 59, 230, 26))
        search.setPlaceholderString_("Search rules")
        search.setStringValue_(getattr(self.controller, "rules_filter", ""))
        self._wire(search, lambda sender: self.controller.filter_rules(
            str(sender.stringValue())))
        root.addSubview_(search)
        if not library:
            root.addSubview_(self._button(
                "More…", (344, content_top + 58, 70, 27),
                lambda sender: self.controller.show_rule_list_menu(sender),
                bordered=False))

        if getattr(self.controller, "rules_loading", False):
            self._render_loading(root, "Loading project rules…")
            return
        data = getattr(self.controller, "rules_data", {}) or {}
        rules = data.get("rules") or []
        query = getattr(self.controller, "rules_filter", "").strip().lower()
        if query:
            rules = [
                rule for rule in rules
                if query in str(rule.get("name") or rule.get("title") or "").lower()
                or query in str(rule.get("id", "")).lower()
            ]
        errors = data.get("errors") or []
        if not rules and not errors:
            self._render_message_state(
                root,
                "No rule definitions" if library else "No rules in this project",
                (
                    "Create a rule in a project to add it to this library."
                    if library
                    else "Add a built-in rule, convert Cursor rules, or create Python."
                ),
                "+ Add rule",
                lambda: (
                    self.controller.begin_add_rule("", None)
                    if library
                    else self.controller.show_add_rule_menu(None)
                ))
            return
        total_height = 12 + (len(errors) + len(rules)) * 76
        scroll, document = self._scroll(
            (0, content_top + 90, self.layout.width,
             max(40, content_height - 90)), total_height)
        root.addSubview_(scroll)
        y = 10
        for error in errors:
            self._render_rule_error_row(document, y, error)
            y += 76
        for rule in rules:
            self._render_rule_row(document, y, rule)
            y += 76

    def _render_rule_row(self, parent: NSView, y: float, rule: dict[str, Any]) -> None:
        library = getattr(
            self.controller, "rules_context", "library") == "library"
        text_x = PAD if library else 116
        text_width = 266 if library else 166
        if not library:
            switch = NSButton.alloc().initWithFrame_(
                NSMakeRect(PAD, y + 12, 96, 24))
            switch.setButtonType_(NSSwitchButton)
            switch.setTitle_("Runs here")
            switch.setState_(
                NSControlStateValueOn if rule.get("enabled")
                else NSControlStateValueOff)
            switch.setAccessibilityLabel_(
                f"Run {rule.get('name') or rule.get('title') or 'rule'} "
                "in this project")
            self._wire(
                switch,
                lambda sender, value=rule: self.controller.toggle_rule(
                    value, sender.state() == NSControlStateValueOn),
            )
            parent.addSubview_(switch)
        parent.addSubview_(self._label(
            rule.get("name") or rule.get("title") or rule.get("id", "Rule"),
            (text_x, y + 5, text_width, 20),
            size=12, bold=True))
        origin = {
            "global": "Shared source",
            "project": "Project source",
            "builtin": "Built-in",
        }.get(rule.get("source_origin") or rule.get("scope"), "Rule")
        override = rule.get("project_override")
        states = [origin]
        if library and rule.get("project_name"):
            states.append(rule["project_name"])
        if override is not None:
            states.append("project selection")
        if rule.get("customized_from"):
            states.append("customized")
        if rule.get("muted"):
            states.append("findings hidden")
        if rule.get("draft_changes"):
            states.append("draft changes")
        warm_status = rule.get("warm_status")
        if warm_status == "failed":
            states.append("check failed")
        parent.addSubview_(self._label(
            " · ".join(states),
            (text_x, y + 28, text_width, 36), size=9.5,
            lines=2, color=NSColor.secondaryLabelColor()))
        parent.addSubview_(self._button(
            "Edit", (286, y + 8, 54, 27),
            lambda _sender, value=rule: self.controller.edit_rule(value),
            bordered=False))
        parent.addSubview_(self._button(
            "Actions…", (344, y + 8, 76, 27),
            lambda sender, value=rule: self.controller.show_rule_menu(sender, value),
            bordered=False,
            accessibility=(
                "Actions for "
                f"{rule.get('name') or rule.get('title') or rule.get('id', 'rule')}"
            )))
        self._separator(
            parent, y + 74, text_x, POPOVER_WIDTH - text_x - PAD)

    def _render_rule_error_row(
        self, parent: NSView, y: float, error: dict[str, Any]
    ) -> None:
        name = error.get("name") or error.get("id") or "Unknown rule"
        parent.addSubview_(self._label(
            "RULE COULD NOT LOAD", (PAD, y + 4, 170, 17),
            size=9, bold=True, color=NSColor.systemRedColor()))
        parent.addSubview_(self._label(
            name, (PAD, y + 22, 250, 18), size=11.5, bold=True))
        parent.addSubview_(self._label(
            error.get("load_error") or error.get("error") or "Unknown import error",
            (PAD, y + 42, 270, 28), size=9.5, lines=2,
            color=NSColor.secondaryLabelColor()))
        parent.addSubview_(self._button(
            "Open", (286, y + 8, 54, 27),
            lambda _sender, value=error: self.controller.open_rule_source(value),
            bordered=False))
        parent.addSubview_(self._button(
            "Actions…", (344, y + 8, 76, 27),
            lambda sender, value=error: self.controller.show_rule_menu(
                sender, value),
            bordered=False,
            accessibility=f"Actions for broken rule {name}"))
        self._separator(parent, y + 74, PAD, POPOVER_WIDTH - 2 * PAD)

    # --- Projects -------------------------------------------------------
    def _render_projects(self, root: NSView, snapshot: UISnapshot) -> None:
        content_top = self.layout.header_height
        content_height = (
            self.layout.height - self.layout.header_height
            - self.layout.footer_height
        )
        projects = snapshot.projects
        if not projects:
            self._render_message_state(
                root, "No Cursor projects found",
                "Open a project in Cursor, then run “rap init --scan” there.")
            return
        total_height = 12 + len(projects) * 86
        scroll, document = self._scroll(
            (0, content_top, self.layout.width, max(40, content_height)),
            total_height)
        root.addSubview_(scroll)
        y = 10
        for project in projects:
            switch = NSButton.alloc().initWithFrame_(NSMakeRect(PAD, y + 17, 38, 24))
            switch.setButtonType_(NSSwitchButton)
            switch.setTitle_("")
            switch.setState_(
                NSControlStateValueOn if project.get("monitoring")
                else NSControlStateValueOff)
            switch.setAccessibilityLabel_(
                "Monitor "
                f"{project.get('name') or _project_name(project.get('path', ''))}"
            )
            self._wire(switch, lambda sender, value=project: self.controller.toggle_project(
                value, sender.state() == NSControlStateValueOn))
            document.addSubview_(switch)
            document.addSubview_(self._label(
                project.get("name") or _project_name(project.get("path", "")),
                (62, y + 7, 250, 20), size=12, bold=True))
            status = str(project.get("status", "idle")).replace("_", " ").title()
            activity = "Agent active" if project.get("active") else (
                f"Last event {_relative_time(project.get('last_event_ts'))} ago"
                if project.get("last_event_ts") else "No agent activity observed")
            summary = (
                f"{status} · {project.get('enabled_rule_count', 0)}/"
                f"{project.get('rule_count', 0)} rules · {activity}"
            )
            status_color = (
                NSColor.systemRedColor()
                if project.get("status") == "failed"
                else NSColor.systemOrangeColor()
                if project.get("status") in ("degraded", "warming", "setup_needed")
                else NSColor.secondaryLabelColor()
            )
            document.addSubview_(self._label(
                summary, (62, y + 29, 172, 42), size=9.5, lines=3,
                color=status_color))
            if project.get("open_count"):
                document.addSubview_(self._label(
                    str(project["open_count"]), (368, y + 9, 24, 18),
                    size=11, bold=True))
            document.addSubview_(self._button(
                "+ Rule", (244, y + 49, 58, 25),
                lambda sender, value=project: self.controller.begin_add_rule(
                    value.get("path", ""), sender),
                bordered=False))
            document.addSubview_(self._button(
                "Rules", (306, y + 49, 48, 25),
                lambda _sender, value=project: self.controller.open_manage_rules(
                    value.get("path", "")),
                bordered=False))
            document.addSubview_(self._button(
                "Actions…", (356, y + 49, 68, 25),
                lambda sender, value=project: self.controller.show_project_menu(sender, value),
                bordered=False,
                accessibility=(
                    "Actions for "
                    f"{project.get('name') or _project_name(project.get('path', ''))}"
                )))
            self._separator(document, y + 84, 62, POPOVER_WIDTH - 76)
            y += 86

    # --- states ---------------------------------------------------------
    def _render_loading(self, root: NSView, message: str, top: float | None = None) -> None:
        top = self.layout.header_height + 45 if top is None else top + 45
        spinner = NSProgressIndicator.alloc().initWithFrame_(
            NSMakeRect(POPOVER_WIDTH / 2 - 10, top, 20, 20))
        spinner.setStyle_(NSProgressIndicatorStyleSpinning)
        spinner.setIndeterminate_(True)
        spinner.startAnimation_(None)
        root.addSubview_(spinner)
        root.addSubview_(self._label(
            message, (PAD, top + 32, POPOVER_WIDTH - 2 * PAD, 22),
            size=11, color=NSColor.secondaryLabelColor()))

    def _render_message_state(
        self,
        root: NSView,
        title: str,
        message: str,
        action_title: str | None = None,
        action: Callable[[], None] | None = None,
        *,
        top: float | None = None,
    ) -> None:
        y = self.layout.header_height + 30 if top is None else top + 30
        root.addSubview_(self._label(
            title, (PAD + 20, y, POPOVER_WIDTH - 2 * PAD - 40, 24),
            size=14, bold=True))
        root.addSubview_(self._label(
            message, (PAD + 20, y + 30, POPOVER_WIDTH - 2 * PAD - 40, 52),
            size=11, lines=3, color=NSColor.secondaryLabelColor()))
        if action_title and action:
            root.addSubview_(self._button(
                action_title, (PAD + 20, y + 78, 130, 30),
                lambda _sender: action(),
                role="primary"))

    # --- action menus ---------------------------------------------------
    def popup_menu(
        self,
        sender: Any,
        items: list[tuple[str, Callable[[], None], bool]],
    ) -> None:
        menu = NSMenu.alloc().initWithTitle_("Actions")
        self._menus.append(menu)
        tags: list[int] = []
        for title, callback, enabled in items:
            if title == "-":
                menu.addItem_(NSMenuItem.separatorItem())
                continue
            item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                title, "invoke:", "")
            tags.append(self._wire_menu(item, callback))
            item.setEnabled_(enabled)
            menu.addItem_(item)
        view = sender if sender is not None else getattr(self.controller, "content_view", None)
        if view is not None:
            try:
                menu.popUpMenuPositioningItem_atLocation_inView_(
                    None, (0, view.bounds().size.height), view)
            finally:
                for tag in tags:
                    self._menu_callbacks.pop(tag, None)
