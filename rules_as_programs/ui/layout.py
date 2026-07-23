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
