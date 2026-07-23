"""Rule loading: import ``.py`` rule files and collect decorated rules.

A rule file defines one (or more) functions decorated with
:func:`rules_as_programs.rule`. We import each file and collect any function
carrying the decorator's metadata. Rules resolve from two scopes -- global
(``~/.cursor/rules-as-programs/rules``) then project
(``<repo>/.cursor/rules-as-programs/rules``) -- with project overriding global
by immutable 16-character ``id``. New files live at ``rules/<id>/rule.py``; legacy
flat files remain loadable until their first structured save migrates them.

Importing rule files executes them. That is the same trust model as
``.cursor/hooks`` scripts: they are the user's own code, in their own repo.
"""

from __future__ import annotations

import importlib.util
import itertools
import secrets
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .. import config
from ..sdk import RULE_ATTR, RuleDef

_counter = itertools.count()
RULE_ID_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"


def _encode_rule_id(raw: bytes) -> str:
    value = int.from_bytes(raw, "big")
    chars = []
    for _ in range(16):
        chars.append(RULE_ID_ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def new_rule_id() -> str:
    return _encode_rule_id(secrets.token_bytes(10))


def is_rule_id(value: str | None) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 16
        and all(char in RULE_ID_ALPHABET for char in value)
    )


@dataclass
class LoadedRule:
    id: str
    title: str
    severity: str
    on: list[str]
    fn: Callable
    inputs: list[str] = field(default_factory=list)
    probes: dict[str, str] = field(default_factory=dict)
    channel: str = "finding"
    spec: str | None = None
    examples: list[tuple[str, str]] = field(default_factory=list)
    scope: str = "project"
    source_path: str = ""
    working_source_path: str = ""

    @classmethod
    def from_def(cls, d: RuleDef, scope: str, path: str) -> "LoadedRule":
        if not is_rule_id(d.id):
            raise ValueError("rule id must be a 16-character Crockford Base32 value")
        return cls(id=d.id, title=d.title, severity=d.severity, on=list(d.on),
                   inputs=list(d.inputs),
                   probes=dict(d.probes),
                   channel=d.channel,
                   fn=d.fn, spec=d.spec, examples=list(d.examples),
                   scope=scope, source_path=path,
                   working_source_path=path)


@dataclass
class RuleLoadError:
    path: str
    scope: str
    error: str


def _import_file(path: Path):
    """Import a .py file under a fresh module name (so edits are picked up)."""
    mod_name = f"rap_rule_{next(_counter)}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # may raise; caller handles
    return module


def rules_in_module(module) -> list[RuleDef]:
    seen: dict[int, RuleDef] = {}
    for value in vars(module).values():
        rd = getattr(value, RULE_ATTR, None)
        if isinstance(rd, RuleDef) and id(rd) not in seen:
            seen[id(rd)] = rd
    return list(seen.values())


def load_rule_file(path: Path, scope: str) -> list[LoadedRule]:
    rules, _error = _load_rule_file_result(path, scope)
    return rules


def _load_rule_file_result(
    path: Path, scope: str
) -> tuple[list[LoadedRule], RuleLoadError | None]:
    try:
        module = _import_file(path)
    except Exception as exc:
        message = "".join(traceback.format_exception_only(type(exc), exc)).strip()
        return [], RuleLoadError(str(path), scope, message)
    if module is None:
        return [], RuleLoadError(str(path), scope, "Could not import rule module")
    try:
        rules = [
            LoadedRule.from_def(rd, scope, str(path))
            for rd in rules_in_module(module)
        ]
    except ValueError as exc:
        return [], RuleLoadError(str(path), scope, str(exc))
    if not rules:
        return [], RuleLoadError(str(path), scope, "No @rule-decorated function found")
    return rules, None


def rule_paths(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    return sorted(directory.glob("*/rule.py"))


def load_rules_with_errors(
    project_root: str | None = None,
) -> tuple[list[LoadedRule], list[RuleLoadError]]:
    rules: dict[str, LoadedRule] = {}
    errors: list[RuleLoadError] = []
    for path in rule_paths(config.global_rules_dir()):
        loaded, error = _load_rule_file_result(path, "global")
        if error:
            errors.append(error)
        for r in loaded:
            rules[r.id] = r
    if project_root:
        for path in rule_paths(config.project_rules_dir(project_root)):
            loaded, error = _load_rule_file_result(path, "project")
            if error:
                errors.append(error)
            for r in loaded:
                rules[r.id] = r
    return list(rules.values()), errors


def load_rules(project_root: str | None = None) -> list[LoadedRule]:
    rules, _errors = load_rules_with_errors(project_root)
    return rules
