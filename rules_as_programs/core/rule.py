"""Rule loading: import ``.py`` rule files and collect decorated rules.

A rule file defines one (or more) functions decorated with
:func:`rules_as_programs.rule`. We import each file and collect any function
carrying the decorator's metadata. Rules resolve from two scopes -- global
(``~/.cursor/rules-as-programs/rules``) then project
(``<repo>/.cursor/rules-as-programs/rules``) -- with project overriding global
by immutable UUID ``id``. New files live at ``rules/<uuid>/rule.py``; legacy
flat files remain loadable until their first structured save migrates them.

Importing rule files executes them. That is the same trust model as
``.cursor/hooks`` scripts: they are the user's own code, in their own repo.
"""

from __future__ import annotations

import importlib.util
import itertools
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .. import config
from ..sdk import RULE_ATTR, RuleDef

_counter = itertools.count()
RULE_UUID_NAMESPACE = uuid.UUID("ae940bdb-cd60-48b0-bca8-b5e3a25285a7")


def is_rule_uuid(value: str | None) -> bool:
    try:
        return bool(value) and str(uuid.UUID(str(value))) == str(value).lower()
    except (ValueError, AttributeError, TypeError):
        return False


def legacy_rule_uuid(legacy_id: str) -> str:
    return str(uuid.uuid5(RULE_UUID_NAMESPACE, legacy_id))


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
    legacy_id: str = ""
    slug: str = ""
    spec: str | None = None
    examples: list[tuple[str, str]] = field(default_factory=list)
    scope: str = "project"
    source_path: str = ""
    working_source_path: str = ""

    @classmethod
    def from_def(cls, d: RuleDef, scope: str, path: str) -> "LoadedRule":
        function_slug = d.fn.__name__.replace("_", "-")
        legacy_id = d.id if d.id and not is_rule_uuid(d.id) else function_slug
        rule_id = d.id if is_rule_uuid(d.id) else legacy_rule_uuid(legacy_id)
        return cls(id=rule_id, title=d.title, severity=d.severity, on=list(d.on),
                   inputs=list(d.inputs),
                   probes=dict(d.probes),
                   channel=d.channel,
                   fn=d.fn, spec=d.spec, examples=list(d.examples),
                   scope=scope, source_path=path,
                   working_source_path=path,
                   legacy_id=legacy_id, slug=function_slug)


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
    rules = [LoadedRule.from_def(rd, scope, str(path)) for rd in rules_in_module(module)]
    if not rules:
        return [], RuleLoadError(str(path), scope, "No @rule-decorated function found")
    return rules, None


def rule_paths(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    return sorted({
        *directory.glob("*.py"),
        *directory.glob("*/rule.py"),
    })


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
