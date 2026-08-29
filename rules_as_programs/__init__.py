"""Rules as Programs.

Give agent constraints a life of their own. Each rule becomes an independent,
PAW-backed fuzzy program that observes a coding agent's reasoning and actions
(via Codex lifecycle hooks), judges whether the rule's
requirements are met, and surfaces structured verdicts in a native findings inbox.

The core (events, ledger, rules, engine, store, PAW runtime, daemon) is
agent-agnostic. Only :mod:`rules_as_programs.adapters.codex` is Codex-specific.
"""

__version__ = "0.1.0"

from .sdk import rule, paw_function  # noqa: E402  (public authoring API)

__all__ = ["rule", "paw_function", "__version__"]
