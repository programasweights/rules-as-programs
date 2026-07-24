"""Pure content-fitting metrics for the native popover."""

from __future__ import annotations

from dataclasses import dataclass

POPOVER_WIDTH = 430
POPOVER_MAX_HEIGHT = 600
POPOVER_MIN_HEIGHT = 170
FOOTER_HEIGHT = 38


@dataclass(frozen=True)
class PopoverLayout:
    width: float
    height: float
    header_height: float
    footer_height: float


@dataclass(frozen=True)
class RuleEditorLayout:
    width: float
    height: float
    stacked_metadata: bool


def fit_popover_layout(
    content_height: float,
    *,
    show_status: bool,
    max_height: float = POPOVER_MAX_HEIGHT,
) -> PopoverLayout:
    header = 92 if show_status else 72
    footer = FOOTER_HEIGHT
    height = max(
        POPOVER_MIN_HEIGHT,
        min(max_height, header + footer + max(60, content_height)),
    )
    return PopoverLayout(POPOVER_WIDTH, height, header, footer)


def fit_rule_editor_layout(
    *,
    advanced: bool,
    optional_height: float = 0,
    available_width: float = 1440,
    available_height: float = 900,
) -> RuleEditorLayout:
    """Choose an initial content size without overriding later user resizing."""
    preferred_width = 900.0 if advanced else 760.0
    preferred_height = (680.0 if advanced else 600.0) + max(
        0.0, optional_height)
    width = max(680.0, min(preferred_width, available_width - 40.0))
    height = max(520.0, min(preferred_height, available_height - 80.0))
    return RuleEditorLayout(width, height, width < 720.0)
