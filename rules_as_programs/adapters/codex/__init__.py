"""Codex integration: normalize lifecycle-hook payloads and install hooks."""

from .adapter import CodexAdapter, normalize

__all__ = ["CodexAdapter", "normalize"]
