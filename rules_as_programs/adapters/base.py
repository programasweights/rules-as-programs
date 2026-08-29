"""Adapter interface -- the extension point for supporting new coding agents.

To add a new coding-agent integration, implement an ``Adapter``
that:

1. ``normalize(raw)`` -- turn one raw hook/event payload into zero or more
   normalized :class:`~rules_as_programs.core.events.Event` objects.
2. ``install(scope, project_root)`` -- wire the agent's hook mechanism to feed
   this adapter's client.

The daemon, engine, PAW runtime, verdict store, and tray UI are all
agent-agnostic and are reused unchanged.
"""

from __future__ import annotations

import abc
from typing import Any

from ..core.events import Event


class Adapter(abc.ABC):
    name: str

    @abc.abstractmethod
    def normalize(self, raw: dict[str, Any]) -> list[Event]:
        ...

    @abc.abstractmethod
    def install(self, scope: str, project_root: str | None = None) -> list[str]:
        """Install hooks for ``scope`` ("global"|"project"). Returns notes."""
        ...
