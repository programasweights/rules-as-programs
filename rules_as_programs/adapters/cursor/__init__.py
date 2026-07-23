"""Cursor integration: normalize Cursor Agent Hook payloads into events, and
install the hooks that feed them."""

from .adapter import CursorAdapter, normalize

__all__ = ["CursorAdapter", "normalize"]
