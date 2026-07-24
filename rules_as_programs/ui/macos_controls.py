"""Shared native interaction styles for the macOS UI."""

from __future__ import annotations

from typing import Literal

import objc
from AppKit import (
    NSBezierPath,
    NSBezelStyleInline,
    NSBezelStyleRounded,
    NSButton,
    NSColor,
    NSEventModifierFlagCommand,
    NSEventModifierFlagControl,
    NSEventModifierFlagDeviceIndependentFlagsMask,
    NSEventModifierFlagOption,
    NSEventModifierFlagShift,
    NSFocusRingOnly,
    NSFocusRingTypeExterior,
    NSSetFocusRingStyle,
    NSTrackingActiveInActiveApp,
    NSTrackingArea,
    NSTrackingInVisibleRect,
    NSTrackingMouseEnteredAndExited,
    NSWindow,
)

ButtonRole = Literal["primary", "secondary", "flat", "icon", "destructive"]


def appkit_text_length(value) -> int:
    """Return NSString-compatible UTF-16 units for NSRange clamping."""
    return len(str(value).encode("utf-16-le")) // 2


def style_button(
    button: NSButton,
    *,
    role: ButtonRole = "secondary",
    accessibility: str | None = None,
    tooltip: str | None = None,
) -> NSButton:
    """Apply one predictable visual and accessibility contract to a button."""
    if role in ("flat", "icon"):
        button.setBezelStyle_(NSBezelStyleInline)
        button.setBordered_(False)
        button.setShowsBorderOnlyWhileMouseInside_(False)
        if hasattr(button, "setContentTintColor_"):
            button.setContentTintColor_(NSColor.controlAccentColor())
    else:
        button.setBezelStyle_(NSBezelStyleRounded)
        button.setBordered_(True)
        button.setShowsBorderOnlyWhileMouseInside_(False)
        if role == "primary" and hasattr(button, "setContentTintColor_"):
            button.setContentTintColor_(NSColor.controlAccentColor())
    button.setFocusRingType_(NSFocusRingTypeExterior)
    if role == "destructive" and hasattr(button, "setContentTintColor_"):
        button.setContentTintColor_(NSColor.systemRedColor())
    if accessibility:
        button.setAccessibilityLabel_(accessibility)
    hint = tooltip or accessibility
    if hint:
        button.setToolTip_(hint)
    return button


class RAPCommandWindow(NSWindow):
    """Window-level fallback for Select All in an accessory application."""

    def performKeyEquivalent_(self, event):
        characters = str(event.charactersIgnoringModifiers() or "").lower()
        modifiers = (
            int(event.modifierFlags())
            & int(NSEventModifierFlagDeviceIndependentFlagsMask)
        )
        relevant = modifiers & int(
            NSEventModifierFlagCommand
            | NSEventModifierFlagControl
            | NSEventModifierFlagShift
            | NSEventModifierFlagOption
        )
        if characters == "a" and relevant in (
            int(NSEventModifierFlagCommand),
            int(NSEventModifierFlagControl),
        ):
            responder = self.firstResponder()
            if responder is not None and responder.respondsToSelector_("selectAll:"):
                responder.selectAll_(self)
                return True
        return objc.super(RAPCommandWindow, self).performKeyEquivalent_(event)


class RAPHoverButton(NSButton):
    """Accent-colored action button with an explicit hover surface."""

    def initWithFrame_(self, frame):
        self = objc.super(RAPHoverButton, self).initWithFrame_(frame)
        if self is None:
            return None
        self._rap_hovered = False
        self._rap_tracking_area = None
        self.setBordered_(False)
        self.setFocusRingType_(NSFocusRingTypeExterior)
        return self

    def updateTrackingAreas(self):
        area = getattr(self, "_rap_tracking_area", None)
        if area is not None:
            self.removeTrackingArea_(area)
        objc.super(RAPHoverButton, self).updateTrackingAreas()
        options = (
            NSTrackingMouseEnteredAndExited
            | NSTrackingActiveInActiveApp
            | NSTrackingInVisibleRect
        )
        area = NSTrackingArea.alloc().initWithRect_options_owner_userInfo_(
            self.bounds(), options, self, None
        )
        self.addTrackingArea_(area)
        self._rap_tracking_area = area

    def mouseEntered_(self, _event):
        self._rap_hovered = True
        self.setNeedsDisplay_(True)

    def mouseExited_(self, _event):
        self._rap_hovered = False
        self.setNeedsDisplay_(True)

    def highlight_(self, highlighted):
        objc.super(RAPHoverButton, self).highlight_(highlighted)
        self.setNeedsDisplay_(True)

    def drawRect_(self, dirty_rect):
        path = NSBezierPath.bezierPathWithRoundedRect_xRadius_yRadius_(
            self.bounds(), 6.0, 6.0
        )
        if self.isHighlighted():
            NSColor.controlAccentColor().colorWithAlphaComponent_(0.22).setFill()
            path.fill()
        elif getattr(self, "_rap_hovered", False):
            NSColor.controlAccentColor().colorWithAlphaComponent_(0.13).setFill()
            path.fill()
        objc.super(RAPHoverButton, self).drawRect_(dirty_rect)

    @objc.python_method
    def hovered(self) -> bool:
        return bool(getattr(self, "_rap_hovered", False))


class RAPInteractiveRow(NSButton):
    """A full-row button with explicit hover, press, and keyboard focus."""

    def initWithFrame_(self, frame):
        self = objc.super(RAPInteractiveRow, self).initWithFrame_(frame)
        if self is None:
            return None
        self._rap_hovered = False
        self._rap_tracking_area = None
        self.setTitle_("")
        self.setBordered_(False)
        self.setFocusRingType_(NSFocusRingTypeExterior)
        return self

    def updateTrackingAreas(self):
        area = getattr(self, "_rap_tracking_area", None)
        if area is not None:
            self.removeTrackingArea_(area)
        objc.super(RAPInteractiveRow, self).updateTrackingAreas()
        options = (
            NSTrackingMouseEnteredAndExited
            | NSTrackingActiveInActiveApp
            | NSTrackingInVisibleRect
        )
        area = NSTrackingArea.alloc().initWithRect_options_owner_userInfo_(
            self.bounds(), options, self, None
        )
        self.addTrackingArea_(area)
        self._rap_tracking_area = area

    def mouseEntered_(self, _event):
        self._rap_hovered = True
        self.setNeedsDisplay_(True)

    def mouseExited_(self, _event):
        self._rap_hovered = False
        self.setNeedsDisplay_(True)

    def highlight_(self, highlighted):
        objc.super(RAPInteractiveRow, self).highlight_(highlighted)
        self.setNeedsDisplay_(True)

    def acceptsFirstResponder(self):
        return True

    def becomeFirstResponder(self):
        accepted = objc.super(RAPInteractiveRow, self).becomeFirstResponder()
        self.setNeedsDisplay_(True)
        return accepted

    def resignFirstResponder(self):
        accepted = objc.super(RAPInteractiveRow, self).resignFirstResponder()
        self.setNeedsDisplay_(True)
        return accepted

    def drawRect_(self, dirty_rect):
        objc.super(RAPInteractiveRow, self).drawRect_(dirty_rect)
        path = NSBezierPath.bezierPathWithRoundedRect_xRadius_yRadius_(
            self.bounds(), 6.0, 6.0
        )
        if self.isHighlighted():
            NSColor.controlAccentColor().colorWithAlphaComponent_(0.18).setFill()
            path.fill()
        elif getattr(self, "_rap_hovered", False):
            NSColor.controlAccentColor().colorWithAlphaComponent_(0.13).setFill()
            path.fill()
        window = self.window()
        if window is not None and window.firstResponder() is self:
            NSSetFocusRingStyle(NSFocusRingOnly)
            NSColor.keyboardFocusIndicatorColor().setFill()
            path.fill()

    @objc.python_method
    def hovered(self) -> bool:
        """Expose hover state for deterministic AppKit tests."""
        return bool(getattr(self, "_rap_hovered", False))
