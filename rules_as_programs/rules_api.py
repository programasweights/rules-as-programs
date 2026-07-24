"""Rule-management operations shared by the tray and the CLI.

All file-level operations work on ``rules/<id>/rule.py``. Assignment,
hidden-finding state, and per-project monitoring are kept in explicit
config/state files and never rewrite the user's source. Compile + test need a
warm PAW runtime, so those
are driven by the daemon (which keeps one warm).
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import threading
import time
import tokenize
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import Any

from . import config, scaffold
from .core.events import ALL_KINDS
from .core import revisions
from .core.rule import (
    LoadedRule, is_rule_id, load_rule_file, load_rule_file_with_error,
    load_rules, new_rule_id, rule_definition_count, rule_paths,
)
from .sdk import RULE_ATTR, RuleDef, SEVERITIES

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows uses the process lock.
    fcntl = None


_RULE_MUTATION_LOCK = threading.RLock()
_RULE_MUTATION_LOCAL = threading.local()


@contextmanager
def _rule_mutation_lock():
    """Serialize source validation and replacement across UI/CLI processes."""
    with _RULE_MUTATION_LOCK:
        depth = int(getattr(_RULE_MUTATION_LOCAL, "depth", 0))
        _RULE_MUTATION_LOCAL.depth = depth + 1
        if depth:
            try:
                yield
            finally:
                _RULE_MUTATION_LOCAL.depth = depth
            return
        lock_file = (config.state_dir() / "rule-mutations.lock").open("a+")
        try:
            if fcntl is not None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()
            _RULE_MUTATION_LOCAL.depth = 0


def _serialized_rule_mutation(function):
    @wraps(function)
    def serialized(*args, **kwargs):
        with _rule_mutation_lock():
            return function(*args, **kwargs)

    return serialized


# --- listing / reading -----------------------------------------------------

def _source_digest(source: str | bytes) -> str:
    raw = source if isinstance(source, bytes) else source.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _decode_python_source(source: bytes) -> str:
    encoding, _lines = tokenize.detect_encoding(io.BytesIO(source).readline)
    return source.decode(encoding)


def _static_rule_definition_count(source: bytes) -> int | None:
    try:
        tree = ast.parse(_decode_python_source(source))
    except (SyntaxError, UnicodeError):
        return None
    count = 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if (
                isinstance(target, ast.Name) and target.id == "rule"
            ) or (
                isinstance(target, ast.Attribute) and target.attr == "rule"
            ):
                count += 1
                break
    return count


def _definition_identity(
    rule_id: str,
    scope: str,
    source_path: str | os.PathLike[str],
    project_root: str | None,
    source: str | bytes,
) -> dict[str, str] | None:
    if scope not in ("global", "project"):
        return None
    return {
        "rule_id": rule_id,
        "scope": scope,
        "project_root": str(project_root or "") if scope == "project" else "",
        "source_path": str(Path(source_path).expanduser().resolve()),
        "source_hash": _source_digest(source),
    }


def _summary(
    r: LoadedRule,
    project_root: str | None,
    shared_ids: set[str] | None = None,
) -> dict[str, Any]:
    mute = mute_info(r.id, project_root)
    assignment = enabled_state(r.id, project_root)
    customized = bool(
        project_root
        and r.scope == "project"
        and (
            r.id in shared_ids
            if shared_ids is not None
            else any(item.id == r.id for item in load_rules(None))
        )
    )
    if (
        r.scope == "project"
        and not customized
        and assignment.get("project_override") is None
        and assignment.get("global_default") is not False
    ):
        assignment = {
            **assignment,
            "assignment_origin": "project_default",
            "effective_enabled": True,
        }
    try:
        source_bytes = Path(r.source_path).read_bytes()
    except OSError:
        source_bytes = b""
    try:
        source = _decode_python_source(source_bytes)
    except (SyntaxError, UnicodeError):
        source = ""
    revision = revisions.working_status(r.id, r.source_path, source)
    definition = _definition_identity(
        r.id, r.scope, r.source_path, project_root, source_bytes)
    return {
        "id": r.id,
        "name": r.title,
        "title": r.title,
        "severity": r.severity,
        "scope": r.scope,
        "on": r.on,
        "inputs": r.inputs,
        "probes": r.probes,
        "channel": r.channel,
        "n_examples": len(r.examples),
        "source_path": r.source_path,
        "enabled": assignment["effective_enabled"],
        **assignment,
        "source_origin": r.scope,
        "customized_from": "shared" if customized else "",
        "muted": mute["muted"],
        "mute_until": mute["until"],
        "mute_scope": mute["scope"],
        "paw": bool(r.spec),
        "definition": definition,
        **revision,
    }


def list_rules(project_root: str | None) -> list[dict[str, Any]]:
    loaded = load_rules(project_root or None)
    return [_summary(r, project_root) for r in loaded]


def list_rule_library_with_errors(
    project_roots: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """List source definitions, not one project's effective merged rules."""
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    builtin_ids = {
        loaded[0].id
        for path in scaffold.builtin_rules()
        if (loaded := load_rule_file(path, "builtin"))
    }
    shared_rules: list[LoadedRule] = []
    for path in rule_paths(config.global_rules_dir()):
        loaded, error = load_rule_file_with_error(path, "global")
        shared_rules.extend(loaded)
        if error:
            errors.append(summarize_rule_error(
                error.path, error.scope, error.error,
                shared_available=False))
    shared_ids = {rule.id for rule in shared_rules}
    for rule in shared_rules:
        summary = _summary(rule, None, shared_ids)
        summary.update({
            "project_root": "",
            "project_name": "",
            "is_builtin": rule.id in builtin_ids,
            "installed": True,
        })
        rows.append(summary)
        seen.add((rule.id, str(Path(rule.source_path).resolve())))
    for project_root in project_roots:
        for path in rule_paths(config.project_rules_dir(project_root)):
            loaded, error = load_rule_file_with_error(path, "project")
            if error:
                errors.append(summarize_rule_error(
                    error.path,
                    error.scope,
                    error.error,
                    project_root,
                    shared_available=path.parent.name in shared_ids,
                ))
            for rule in loaded:
                key = (rule.id, str(path.resolve()))
                if key in seen:
                    continue
                summary = _summary(rule, project_root, shared_ids)
                summary["project_root"] = project_root
                summary["project_name"] = Path(project_root).name
                summary["is_builtin"] = rule.id in builtin_ids
                summary["installed"] = True
                rows.append(summary)
                seen.add(key)
    return rows, errors


def list_rule_library(project_roots: list[str]) -> list[dict[str, Any]]:
    rows, _errors = list_rule_library_with_errors(project_roots)
    return rows


def summarize_rule_error(
    path_value: str,
    scope: str,
    error: str,
    project_root: str | None = None,
    *,
    shared_available: bool | None = None,
) -> dict[str, Any]:
    path = Path(path_value).expanduser().absolute()
    try:
        source = path.read_bytes()
    except OSError:
        source = b""
    rule_id = path.parent.name
    owner = str(project_root or "") if scope == "project" else ""
    return {
        "id": rule_id,
        "name": rule_id,
        "title": rule_id,
        "scope": scope,
        "source_origin": scope,
        "source_path": str(path),
        "project_root": owner,
        "load_error": error,
        "invalid": True,
        "customized_from": (
            "shared"
            if scope == "project"
            and (
                shared_available
                if shared_available is not None
                else bool(_usable_shared_definition(rule_id))
            )
            else ""
        ),
        "definition": _definition_identity(
            rule_id, scope, path, owner, source),
    }


def list_rule_library_errors(project_roots: list[str]) -> list[dict[str, Any]]:
    _rows, errors = list_rule_library_with_errors(project_roots)
    return errors


def _find_rule_file(rule_id: str, project_root: str | None) -> tuple[Path, str] | None:
    candidates: list[tuple[Path, str]] = []
    if project_root:
        candidates.append((
            config.project_rules_dir(project_root) / rule_id / "rule.py",
            "project",
        ))
    candidates.append((config.global_rules_dir() / rule_id / "rule.py", "global"))
    for path, scope in candidates:
        if path.exists():
            return path, scope
    # fall back to scanning loaded rules (filename may differ from id)
    for r in load_rules(project_root or None):
        if rule_id == r.id and r.source_path:
            return Path(r.source_path), r.scope
    return None


def get_rule(rule_id: str, project_root: str | None) -> dict[str, Any] | None:
    metadata: dict[str, Any] = {}
    for loaded in load_rules(project_root or None):
        if loaded.id == rule_id:
            metadata = {
                "title": loaded.title,
                "severity": loaded.severity,
                "on": list(loaded.on),
                "inputs": list(loaded.inputs),
                "probes": dict(loaded.probes),
                "channel": loaded.channel,
                "n_examples": len(loaded.examples),
                "paw": bool(loaded.spec),
            }
            break
    found = _find_rule_file(rule_id, project_root)
    if not found:
        src = None
        bundled_rule = None
        for candidate in scaffold.builtin_rules():
            loaded = load_rule_file(candidate, "builtin")
            if loaded and (
                rule_id == loaded[0].id or rule_id == candidate.stem
            ):
                src, bundled_rule = candidate, loaded[0]
                break
        if src and bundled_rule:
            source = _decode_python_source(src.read_bytes())
            if not metadata:
                metadata = {
                    "name": bundled_rule.title,
                    "title": bundled_rule.title,
                    "severity": bundled_rule.severity,
                    "on": list(bundled_rule.on),
                    "inputs": list(bundled_rule.inputs),
                    "probes": dict(bundled_rule.probes),
                    "channel": bundled_rule.channel,
                    "n_examples": len(bundled_rule.examples),
                    "paw": bool(bundled_rule.spec),
                }
            return {
                "id": bundled_rule.id,
                "scope": "builtin",
                "source": source,
                "path": str(src),
                "enabled": is_enabled(bundled_rule.id, project_root),
                **enabled_state(bundled_rule.id, project_root),
                "muted": is_muted(bundled_rule.id, project_root),
                "definition": None,
                **revisions.working_status(
                    bundled_rule.id, str(src), source),
                **metadata,
            }
        return None
    path, scope = found
    loaded_rules = load_rule_file(path, scope)
    loaded_rule = next(
        (item for item in loaded_rules if rule_id == item.id),
        loaded_rules[0] if loaded_rules else None,
    )
    resolved_id = loaded_rule.id if loaded_rule else rule_id
    if loaded_rule:
        metadata = {
            "name": loaded_rule.title,
            "title": loaded_rule.title,
            "severity": loaded_rule.severity,
            "on": list(loaded_rule.on),
            "inputs": list(loaded_rule.inputs),
            "probes": dict(loaded_rule.probes),
            "channel": loaded_rule.channel,
            "n_examples": len(loaded_rule.examples),
            "paw": bool(loaded_rule.spec),
        }
    source_bytes = path.read_bytes()
    source = _decode_python_source(source_bytes)
    customized_from = (
        "shared"
        if (
            scope == "project"
            and _usable_shared_definition(resolved_id) is not None
        )
        else ""
    )
    return {
        "id": resolved_id,
        "scope": scope,
        "source": source,
        "path": str(path),
        "enabled": is_enabled(resolved_id, project_root),
        **enabled_state(resolved_id, project_root),
        "muted": is_muted(resolved_id, project_root),
        "customized_from": customized_from,
        "definition": _definition_identity(
            resolved_id, scope, path, project_root, source_bytes),
        **revisions.working_status(resolved_id, str(path), source),
        **metadata,
    }


# --- writing ---------------------------------------------------------------

def _rules_dir(scope: str, project_root: str | None) -> Path:
    if scope == "global":
        return config.global_rules_dir()
    return config.project_rules_dir(project_root or Path.cwd())


def validate_source(source: str) -> tuple[bool, str, str | None]:
    """Return (ok, error, rule_id). Executes the source in a throwaway namespace
    and confirms it defines a @rule-decorated function."""
    ns: dict[str, Any] = {"__name__": "rap_rule_check"}
    try:
        exec(compile(source, "<rule>", "exec"), ns)
    except Exception as exc:  # syntax or import/runtime error
        return False, f"{type(exc).__name__}: {exc}", None
    for value in ns.values():
        rd = getattr(value, RULE_ATTR, None)
        if isinstance(rd, RuleDef):
            return True, "", rd.id
    return False, "no @rule-decorated function found", None


def check_source_syntax(source: str) -> tuple[bool, str]:
    """Side-effect-free live validation used while the user is typing."""
    try:
        tree = ast.parse(source, filename="<rule>")
    except SyntaxError as exc:
        location = f"line {exc.lineno}" if exc.lineno else "unknown line"
        return False, f"SyntaxError at {location}: {exc.msg}"
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Name) and target.id == "rule":
                return True, ""
            if isinstance(target, ast.Attribute) and target.attr == "rule":
                return True, ""
    return False, "no @rule-decorated function found"


def spec_examples(spec: str | None) -> list[tuple[str, str]]:
    """Parse ``Input:``/``Output:`` cases embedded in a PAW spec."""
    if not spec:
        return []
    examples: list[tuple[str, str]] = []
    current: list[str] | None = None
    for line in spec.splitlines():
        if line.startswith("Input:"):
            current = [line[len("Input:"):].lstrip()]
            continue
        if line.startswith("Output:") and current is not None:
            value = line[len("Output:"):].strip()
            examples.append(("\n".join(current).strip(), value))
            current = None
            continue
        if current is not None:
            current.append(line)
    return [(text, label) for text, label in examples if text and label]


def _is_rule_decorator(node: ast.expr) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    return (
        isinstance(target, ast.Name) and target.id == "rule"
    ) or (
        isinstance(target, ast.Attribute) and target.attr == "rule"
    )


def source_projection(source: str) -> dict[str, Any]:
    """Project canonical Python into safe function/config editor fields."""
    try:
        tree = ast.parse(source, filename="<rule>")
    except SyntaxError as exc:
        return {"ok": False, "error": f"SyntaxError: {exc.msg}", "source": source}
    functions = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(_is_rule_decorator(item) for item in node.decorator_list)
    ]
    if len(functions) != 1:
        return {
            "ok": False,
            "error": f"Expected exactly one @rule function; found {len(functions)}.",
            "source": source,
            "custom": True,
        }
    function = functions[0]
    decorator = next(
        item for item in function.decorator_list if _is_rule_decorator(item))
    values: dict[str, Any] = {}
    inputs_declared = False
    custom = not isinstance(decorator, ast.Call)
    if isinstance(decorator, ast.Call):
        for keyword in decorator.keywords:
            if keyword.arg in (
                "id", "name", "title", "on", "inputs", "probes", "channel",
                "severity"
            ):
                try:
                    values[keyword.arg] = ast.literal_eval(keyword.value)
                    if keyword.arg == "inputs":
                        inputs_declared = True
                except (ValueError, TypeError):
                    custom = True
    on = values.get("on", [])
    inputs = values.get("inputs", [])
    probes = values.get("probes", {})
    severity = values.get("severity", "warn")
    channel = values.get("channel", "finding")
    raw_id = values.get("id", "")
    resolved_id = raw_id if is_rule_id(raw_id) else ""
    if not resolved_id:
        custom = True
    explicit_name = values.get("name") or values.get("title")
    if not isinstance(on, list) or not all(isinstance(item, str) for item in on):
        custom = True
    if not isinstance(inputs, list) or not all(isinstance(item, str) for item in inputs):
        custom = True
    if not isinstance(probes, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in probes.items()
    ):
        custom = True
    if not isinstance(severity, str):
        custom = True
    if not isinstance(channel, str):
        custom = True
    has_probes = bool(probes)
    if not inputs_declared:
        inferred: list[str] = []
        for call in (
            node for node in ast.walk(function) if isinstance(node, ast.Call)
        ):
            target = call.func
            if not (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "ctx"
            ):
                continue
            if target.attr == "evidence":
                for keyword in call.keywords:
                    if keyword.arg in ("latest", "include"):
                        try:
                            kinds = ast.literal_eval(keyword.value)
                        except (ValueError, TypeError):
                            continue
                        for kind in kinds if isinstance(kinds, list) else []:
                            if isinstance(kind, str) and kind not in inferred:
                                inferred.append(kind)
                    elif keyword.arg == "probes":
                        has_probes = True
            elif target.attr in ("latest", "events"):
                for argument in call.args:
                    try:
                        kind = ast.literal_eval(argument)
                    except (ValueError, TypeError):
                        continue
                    if isinstance(kind, str) and kind not in inferred:
                        inferred.append(kind)
            elif target.attr == "run":
                has_probes = True
        if inferred:
            inputs = inferred
    lines = source.splitlines(keepends=True)
    function_source = "".join(lines[function.lineno - 1:function.end_lineno])
    spec = ""
    for node in tree.body:
        if (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and isinstance(getattr(node, "value", None), ast.Constant)
            and isinstance(node.value.value, str)
        ):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == "SPEC" for target in targets):
                spec = node.value.value
                break
    executable_body = function.body[1:] if (
        function.body
        and isinstance(function.body[0], ast.Expr)
        and isinstance(function.body[0].value, ast.Constant)
        and isinstance(function.body[0].value.value, str)
    ) else function.body
    managed_v2_shape = False
    if (
        len(executable_body) == 2
        and isinstance(executable_body[0], ast.Assign)
        and isinstance(executable_body[1], ast.Return)
    ):
        try:
            assignment_source = ast.unparse(executable_body[0].value)
            return_source = ast.unparse(executable_body[1].value)
        except Exception:
            assignment_source = return_source = ""
        managed_v2_shape = (
            assignment_source == "ctx.paw(SPEC)(ctx.input())"
            and return_source.startswith("ctx.finding(")
        )
    managed_fuzzy = (
        MANAGED_FUZZY_MARKER in source
        and bool(spec)
        and managed_v2_shape
    )
    description = ""
    output_labels: list[str] = []
    if spec:
        description = spec.split("Return ONLY one of:", 1)[0].strip()
        match = re.search(
            r"Return ONLY one of:\s*([^\n]+)", spec)
        if match:
            output_labels = [
                item.strip() for item in match.group(1).split(",")
                if item.strip()
            ]
    return {
        "ok": True,
        "source": source,
        "function_source": function_source.rstrip() + "\n",
        "function_name": function.name,
        "id": resolved_id,
        "id_persisted": is_rule_id(raw_id),
        "name": explicit_name or (
            (ast.get_docstring(function) or "").splitlines()[0]
            if ast.get_docstring(function)
            else function.name.replace("_", " ").title()
        ),
        "title": explicit_name or (
            (ast.get_docstring(function) or "").splitlines()[0]
            if ast.get_docstring(function)
            else function.name.replace("_", " ").title()
        ),
        "on": list(on) if isinstance(on, list) else [],
        "inputs": list(inputs) if isinstance(inputs, list) else [],
        "probes": dict(probes) if isinstance(probes, dict) else {},
        "inputs_inferred": bool(not inputs_declared and inputs),
        "has_probes": has_probes,
        "severity": severity if isinstance(severity, str) else "warn",
        "channel": channel if isinstance(channel, str) else "finding",
        "spec": spec,
        "simple_fuzzy": bool(spec),
        "managed_fuzzy": managed_fuzzy,
        "managed_version": 2 if managed_fuzzy else 0,
        "description": description,
        "cases": spec_examples(spec) if managed_fuzzy else [],
        "output_labels": output_labels,
        "allowed_label": (
            "OK" if "OK" in output_labels
            else output_labels[0] if output_labels else "OK"
        ),
        "custom": custom,
        "source_hash": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def _offset(lines: list[str], lineno: int, col: int) -> int:
    return sum(len(line) for line in lines[:lineno - 1]) + col


def patch_rule_identity(
    source: str, rule_id: str, name: str
) -> tuple[bool, str, str]:
    """Persist immutable compact ID and mutable Name into canonical Python."""
    if not is_rule_id(rule_id):
        return False, source, "Rule id must be a valid 16-character ID."
    clean_name = " ".join(str(name).split()).strip()
    if not clean_name:
        return False, source, "Rule name is required."
    try:
        tree = ast.parse(source, filename="<rule>")
    except SyntaxError as exc:
        return False, source, f"SyntaxError: {exc.msg}"
    functions = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(_is_rule_decorator(item) for item in node.decorator_list)
    ]
    if len(functions) != 1:
        return False, source, "Expected exactly one @rule function."
    function = functions[0]
    decorator = next(
        item for item in function.decorator_list if _is_rule_decorator(item))
    if not isinstance(decorator, ast.Call) or any(
        item.arg is None for item in decorator.keywords
    ):
        return False, source, "Custom decorator arguments require Advanced Python."
    unknown = []
    for keyword in decorator.keywords:
        if keyword.arg not in ("id", "name", "title"):
            value = ast.get_source_segment(source, keyword.value)
            unknown.append((keyword.arg, value or "None"))
    arguments = [("id", repr(rule_id)), ("name", repr(clean_name)), *unknown]
    decorator_text = "@rule(\n" + "".join(
        f"    {key}={value},\n" for key, value in arguments
    ) + ")"
    function_name = scaffold.slugify(clean_name).replace("-", "_")
    lines = source.splitlines(keepends=True)
    definition_line = lines[function.lineno - 1]
    name_start = definition_line.find(function.name, function.col_offset)
    if name_start < 0:
        return False, source, "Could not locate function name."
    replacements = [
        (
            _offset(lines, decorator.lineno, 0),
            _offset(lines, decorator.end_lineno, decorator.end_col_offset),
            decorator_text,
        ),
        (
            _offset(lines, function.lineno, name_start),
            _offset(lines, function.lineno, name_start + len(function.name)),
            function_name,
        ),
    ]
    if (
        function.body
        and isinstance(function.body[0], ast.Expr)
        and isinstance(function.body[0].value, ast.Constant)
        and isinstance(function.body[0].value.value, str)
    ):
        value = function.body[0].value
        rendered = '"""' + clean_name.replace('"""', '\\"\\"\\"') + '"""'
        replacements.append((
            _offset(lines, value.lineno, value.col_offset),
            _offset(lines, value.end_lineno, value.end_col_offset),
            rendered,
        ))
    patched = source
    for start, end, replacement in sorted(replacements, reverse=True):
        patched = patched[:start] + replacement + patched[end:]
    ok, error = check_source_syntax(patched)
    return ok, patched, error


def patch_source_projection(
    source: str,
    *,
    on: list[str],
    inputs: list[str],
    severity: str,
    function_source: str,
    spec: str | None = None,
) -> tuple[bool, str, str]:
    """Round-trip safe editor fields back into canonical Python source."""
    projection = source_projection(source)
    if not projection.get("ok"):
        return False, source, projection.get("error", "invalid source")
    if projection.get("custom"):
        return False, source, "Metadata is dynamic; edit it in Full Python."
    try:
        function_tree = ast.parse(function_source, filename="<rule-function>")
    except SyntaxError as exc:
        return False, source, f"Function SyntaxError: {exc.msg}"
    if (
        len(function_tree.body) != 1
        or not isinstance(function_tree.body[0], (ast.FunctionDef, ast.AsyncFunctionDef))
    ):
        return False, source, "Function view must contain exactly one function."
    tree = ast.parse(source, filename="<rule>")
    function = next(
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(_is_rule_decorator(item) for item in node.decorator_list)
    )
    decorator = next(
        item for item in function.decorator_list if _is_rule_decorator(item))
    if not isinstance(decorator, ast.Call) or any(item.arg is None for item in decorator.keywords):
        return False, source, "Custom decorator arguments require Full Python."
    unknown = []
    for keyword in decorator.keywords:
        if keyword.arg not in ("on", "inputs", "severity"):
            value = ast.get_source_segment(source, keyword.value)
            unknown.append((keyword.arg, value or "None"))
    arguments = [
        ("on", repr(list(on))),
        ("inputs", repr(list(inputs))),
        ("severity", repr(severity)),
        *unknown,
    ]
    decorator_text = "@rule(\n" + "".join(
        f"    {name}={value},\n" for name, value in arguments
    ) + ")"
    lines = source.splitlines(keepends=True)
    replacements = [
        (
            _offset(lines, decorator.lineno, 0),
            _offset(lines, decorator.end_lineno, decorator.end_col_offset),
            decorator_text,
        ),
        (
            _offset(lines, function.lineno, 0),
            _offset(lines, function.end_lineno, function.end_col_offset),
            function_source.rstrip(),
        ),
    ]
    if spec is not None:
        for node in tree.body:
            value = getattr(node, "value", None)
            targets = node.targets if isinstance(node, ast.Assign) else (
                [node.target] if isinstance(node, ast.AnnAssign) else [])
            if (
                isinstance(value, ast.Constant) and isinstance(value.value, str)
                and any(isinstance(target, ast.Name) and target.id == "SPEC"
                        for target in targets)
            ):
                rendered = '"""' + spec.replace('"""', '\\"\\"\\"') + '"""'
                replacements.append((
                    _offset(lines, value.lineno, value.col_offset),
                    _offset(lines, value.end_lineno, value.end_col_offset),
                    rendered,
                ))
                break
    patched = source
    for start, end, replacement in sorted(replacements, reverse=True):
        patched = patched[:start] + replacement + patched[end:]
    ok, error = check_source_syntax(patched)
    return ok, patched, error


def validate_editor_source(source: str) -> tuple[bool, str]:
    projection = source_projection(source)
    if not projection.get("ok"):
        return False, projection.get("error", "invalid rule")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return False, f"SyntaxError: {exc.msg}"
    function = next(
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(_is_rule_decorator(item) for item in node.decorator_list)
    )
    positional = [*function.args.posonlyargs, *function.args.args]
    if len(positional) != 1 or positional[0].arg != "ctx":
        return False, "Rule function must take exactly one parameter named ctx."
    if not projection.get("on"):
        return False, "Choose at least one Runs when event."
    unknown_on = set(projection["on"]) - ALL_KINDS
    if unknown_on:
        return False, f"Unknown trigger event(s): {', '.join(sorted(unknown_on))}"
    unknown_inputs = set(projection.get("inputs", [])) - ALL_KINDS
    if unknown_inputs:
        return False, f"Unknown input event(s): {', '.join(sorted(unknown_inputs))}"
    if projection.get("severity") not in SEVERITIES:
        return False, f"Unknown severity: {projection.get('severity')}"
    return True, ""


@_serialized_rule_mutation
def save_rule(rule_id: str, source: str, scope: str, project_root: str | None) -> dict[str, Any]:
    previous = _find_rule_file(rule_id, project_root)
    projection = source_projection(source)
    if not projection.get("ok"):
        return {"ok": False, "error": projection.get("error", "invalid rule")}
    rid = rule_id if is_rule_id(rule_id) else projection["id"]
    if not is_rule_id(rid):
        return {"ok": False, "error": "rule id must be a valid 16-character ID"}
    name = str(projection.get("name") or projection.get("title") or "Rule")
    identity_ok, source, identity_error = patch_rule_identity(source, rid, name)
    if not identity_ok:
        return {"ok": False, "error": identity_error}
    ok, err, found_id = validate_source(source)
    if not ok:
        return {"ok": False, "error": err}
    if found_id != rid:
        return {"ok": False, "error": "source ID does not match rule identity"}
    dest = _rules_dir(scope, project_root)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    folder = (dest / rid).resolve()
    if folder.parent != root:
        return {"ok": False, "error": "rule path escaped rules directory"}
    path = folder / "rule.py"
    if path.exists() and (not previous or previous[0].resolve() != path):
        existing = load_rule_file(path, scope)
        if not existing or existing[0].id != rid:
            return {"ok": False, "error": "a different rule already uses this ID"}
    folder.mkdir(parents=True, exist_ok=True)
    rendered = source if source.endswith("\n") else source + "\n"
    temporary = folder / ".rule.py.tmp"
    temporary.write_text(rendered, encoding="utf-8")
    os.replace(temporary, path)
    stored_bytes = path.read_bytes()
    stored_source = _decode_python_source(stored_bytes)
    if previous:
        previous_path, previous_scope = previous
        if previous_scope == scope and previous_path != path:
            revisions.migrate_source_path(rid, previous_path, path)
            previous_path.unlink(missing_ok=True)
            try:
                previous_path.parent.rmdir()
            except OSError:
                pass
    return {
        "ok": True,
        "id": rid,
        "name": name,
        "title": name,
        "scope": scope,
        "project_root": str(project_root or "") if scope == "project" else "",
        "path": str(path),
        "source": stored_source,
        "projection": source_projection(stored_source),
        "source_hash": _source_digest(stored_bytes),
        "definition": _definition_identity(
            rid, scope, path, project_root, stored_bytes),
        "customized_from": (
            "shared"
            if scope == "project"
            and _usable_shared_definition(rid) is not None
            else ""
        ),
        "is_builtin": rid in set(scaffold.builtin_ids()),
        **revisions.working_status(rid, path, stored_source),
    }


@_serialized_rule_mutation
def save_library_draft(
    rule_id: str,
    source: str,
    *,
    expected_source_hash: str = "",
    expected_absent: bool = False,
) -> dict[str, Any]:
    """CAS-save the canonical source in My Rule Library."""
    target = config.global_rules_dir() / rule_id / "rule.py"
    if expected_absent and target.exists():
        return {
            "ok": False,
            "error": "a rule with this ID already exists in My Rule Library",
            "conflict": True,
        }
    if target.exists():
        current = _source_digest(target.read_bytes())
        if expected_source_hash and current != expected_source_hash:
            return {
                "ok": False,
                "error": "the rule changed in another editor; reload before deploying",
                "current_source_hash": current,
            }
    elif expected_source_hash and not expected_absent:
        return {
            "ok": False,
            "error": "the library rule was removed; reload before deploying",
        }
    if expected_absent:
        disabled = set_enabled(rule_id, False, None)
        if not disabled.get("ok"):
            return disabled
    return save_rule(rule_id, source, "global", None)


@_serialized_rule_mutation
def save_project_draft(
    rule_id: str,
    source: str,
    project_root: str,
    *,
    expected_source_hash: str,
) -> dict[str, Any]:
    path = config.project_rules_dir(project_root) / rule_id / "rule.py"
    if not path.is_file():
        return {"ok": False, "error": "project rule no longer exists"}
    current = _source_digest(path.read_bytes())
    if current != expected_source_hash:
        return {
            "ok": False,
            "error": "the project rule changed in another editor; reload first",
            "current_source_hash": current,
        }
    return save_rule(rule_id, source, "project", project_root)


@_serialized_rule_mutation
def migrate_definition_to_library(
    rule_id: str,
    project_root: str,
    expected_source_path: str,
    expected_source_hash: str,
) -> dict[str, Any]:
    """Move one exact project definition into My Rule Library."""
    path, error = _exact_definition_path(
        rule_id, "project", project_root, expected_source_path)
    if path is None:
        return {"ok": False, "error": error}
    if not path.is_file():
        return {"ok": False, "error": "project rule no longer exists"}
    current_hash = _source_digest(path.read_bytes())
    if current_hash != expected_source_hash:
        return {
            "ok": False,
            "error": "project rule changed; reload before moving it",
            "current_source_hash": current_hash,
        }
    target = config.global_rules_dir() / rule_id / "rule.py"
    if target.exists():
        return {
            "ok": False,
            "error": "My Rule Library already contains this rule ID",
            "conflict": True,
            "path": str(target),
        }
    result = promote_to_shared(rule_id, project_root)
    if not result.get("ok"):
        return result
    info = get_rule(rule_id, None) or {}
    return {**result, "rule": info, "migrated_to_library": True}


@_serialized_rule_mutation
def rename_rule(
    rule_id: str,
    name: str,
    *,
    project_root: str | None,
    project_roots: list[str] | None = None,
    source_override: str | None = None,
) -> dict[str, Any]:
    """Atomically rename Name/function across sources sharing one rule ID."""
    info = get_rule(rule_id, project_root)
    if not info:
        return {"ok": False, "error": "rule not found"}
    if info.get("scope") == "builtin":
        return {
            "ok": False,
            "error": "Customize this built-in for the project before renaming it.",
        }
    paths: list[tuple[Path, str]] = [(Path(info["path"]), info["scope"])]
    if info.get("scope") == "global":
        for root in project_roots or []:
            for path in rule_paths(config.project_rules_dir(root)):
                loaded = load_rule_file(path, "project")
                if loaded and loaded[0].id == rule_id:
                    paths.append((path, "project"))
    unique: dict[str, tuple[Path, str]] = {
        str(path.resolve()): (path, scope) for path, scope in paths
    }
    originals: dict[Path, str] = {}
    patched: dict[Path, str] = {}
    primary_path = Path(info["path"]).resolve()
    for path, _scope in unique.values():
        try:
            source = (
                source_override
                if source_override is not None and path.resolve() == primary_path
                else path.read_text(encoding="utf-8")
            )
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        ok, updated, error = patch_rule_identity(source, rule_id, name)
        if not ok:
            return {"ok": False, "error": error, "path": str(path)}
        valid, error = validate_editor_source(updated)
        if not valid:
            return {"ok": False, "error": error, "path": str(path)}
        originals[path] = source
        patched[path] = updated if updated.endswith("\n") else updated + "\n"
    replaced: list[Path] = []
    try:
        for path, source in patched.items():
            temporary = path.with_name(".rule.rename.tmp")
            temporary.write_text(source, encoding="utf-8")
            os.replace(temporary, path)
            replaced.append(path)
    except OSError as exc:
        for path in replaced:
            temporary = path.with_name(".rule.rollback.tmp")
            temporary.write_text(originals[path], encoding="utf-8")
            os.replace(temporary, path)
        return {"ok": False, "error": str(exc)}
    refreshed = get_rule(rule_id, project_root) or {}
    if refreshed.get("source"):
        refreshed["projection"] = source_projection(refreshed["source"])
        refreshed["source_hash"] = revisions.hash_source(refreshed["source"])
    return {
        "ok": True,
        "id": rule_id,
        "name": name,
        "affected_paths": [str(path) for path in patched],
        "rule": refreshed,
        **{
            key: refreshed.get(key)
            for key in (
                "path", "source", "scope", "projection", "source_hash",
                "definition", "project_root", "customized_from",
            )
            if key in refreshed
        },
    }


MANAGED_FUZZY_MARKER = "# RAP_MANAGED_FUZZY_V2"

DEFAULT_FUZZY_DESCRIPTION = (
    "Decide whether rsync or scp was used to synchronize project source code "
    "instead of Git. Directly copying source code is a violation; transferring "
    "assets, build artifacts, backups, or release packages is allowed."
)
DEFAULT_FUZZY_CASES = [
    ("## Recent activity\n- (shell_exec) $ git push", "OK"),
    (
        "## Recent activity\n"
        "- (shell_exec) $ rsync -av src/ deploy@host:/srv/app/src/",
        "WARNING",
    ),
    (
        "## Recent activity\n"
        "- (shell_exec) $ scp public/logo.png cdn@host:/srv/assets/\n"
        "- (message) Uploaded a static image asset.",
        "OK",
    ),
]


def generate_managed_fuzzy_source(
    rule_id: str,
    name: str,
    description: str,
    *,
    severity: str,
    on: list[str],
    inputs: list[str],
    probes: dict[str, str] | None = None,
    channel: str = "finding",
    cases: list[tuple[str, str]] | None = None,
) -> str:
    if not is_rule_id(rule_id):
        raise ValueError("rule_id must be a valid 16-character ID")
    case_text = "\n\n".join(
        f"Input: {evidence}\nOutput: {label}"
        for evidence, label in (cases or [])
    )
    spec = (
        description.strip()
        + "\nReturn ONLY one of: OK, INFO, WARNING, CRITICAL"
        + (f"\n\n{case_text}" if case_text else "")
    )
    function_name = scaffold.slugify(name).replace("-", "_")
    safe_spec = spec.replace('"""', '\\"\\"\\"')
    safe_name = name.replace('"""', '\\"\\"\\"')
    probe_line = f"    probes={dict(probes)!r},\n" if probes else ""
    channel_line = (
        f"    channel={channel!r},\n" if channel != "finding" else ""
    )
    return (
        "from rules_as_programs import rule\n\n"
        f"{MANAGED_FUZZY_MARKER}\n"
        f'SPEC = """{safe_spec}"""\n\n\n'
        "@rule(\n"
        f"    id={rule_id!r},\n"
        f"    name={name!r},\n"
        f"    on={list(on)!r},\n"
        f"    inputs={list(inputs)!r},\n"
        f"{probe_line}"
        f"{channel_line}"
        f"    severity={severity!r},\n"
        "    spec=SPEC,\n"
        ")\n"
        f"def {function_name}(ctx):\n"
        f'    """{safe_name}"""\n'
        "    decision = ctx.paw(SPEC)(ctx.input())\n"
        f"    return ctx.finding(decision, {name!r})\n"
    )


def draft_rule_source(rule_id: str, title: str | None = None) -> str:
    if not is_rule_id(rule_id):
        raise ValueError("rule_id must be a valid 16-character ID")
    title = title or "Use Git for source synchronization."
    return generate_managed_fuzzy_source(
        rule_id,
        title,
        DEFAULT_FUZZY_DESCRIPTION,
        severity="warn",
        on=["shell_exec", "session_stop"],
        inputs=["shell_exec", "message"],
        cases=DEFAULT_FUZZY_CASES,
    )


PLAIN_RULE_TEMPLATE = '''from rules_as_programs import rule


@rule(id="{rule_id}", name="{title}",
      on=["message"], inputs=["message"], severity="warn")
def {func}(ctx):
    """{title}"""
    if "unsafe phrase" in ctx.input().lower():
        return "The agent used the unsafe phrase."
'''


def draft_plain_rule_source(rule_id: str, title: str | None = None) -> str:
    if not is_rule_id(rule_id):
        raise ValueError("rule_id must be a valid 16-character ID")
    title = title or "Flag a deterministic text pattern."
    func = scaffold.slugify(title).replace("-", "_")
    return PLAIN_RULE_TEMPLATE.format(
        rule_id=rule_id, title=title, func=func)


@_serialized_rule_mutation
def install_builtin(
    rule_id: str,
    scope: str,
    project_root: str | None,
    *,
    overwrite: bool = False,
) -> Path | None:
    return scaffold.add_builtin(
        rule_id, scope, project_root, overwrite=overwrite)


@_serialized_rule_mutation
def create_rule(rule_id: str, scope: str, project_root: str | None,
                title: str | None = None) -> dict[str, Any]:
    requested_name = rule_id if not is_rule_id(rule_id) else ""
    resolved_id = rule_id if is_rule_id(rule_id) else new_rule_id()
    destination = _rules_dir(scope, project_root) / resolved_id / "rule.py"
    same_scope = any(
        loaded.id == resolved_id
        and loaded.scope == scope
        and Path(loaded.source_path).parent == destination.parent
        for loaded in load_rules(project_root or None)
    )
    if destination.exists() or same_scope:
        return {"ok": False, "error": f"rule {resolved_id!r} already exists"}
    title = title or (
        requested_name.replace("-", " ").replace("_", " ").title()
        if requested_name else "Use Git for source synchronization."
    )
    text = draft_rule_source(resolved_id, title)
    res = save_rule(resolved_id, text, scope, project_root)
    if res.get("ok"):
        set_enabled(
            res["id"], False,
            project_root if scope == "project" else None,
        )  # new rules start disabled until reviewed
    return res


def _exact_definition_path(
    rule_id: str,
    scope: str,
    project_root: str | None,
    expected_source_path: str,
) -> tuple[Path | None, str]:
    if scope == "global":
        root = config.global_rules_dir().expanduser().resolve()
    elif scope == "project":
        if not project_root:
            return None, "project_root is required for a project rule"
        root = config.project_rules_dir(project_root).expanduser().resolve()
    else:
        return None, "scope must be 'global' or 'project'"
    if not expected_source_path:
        return None, "exact source path is required for deletion"
    path = Path(expected_source_path).expanduser().resolve()
    if (
        path.name != "rule.py"
        or path.parent.parent != root
        or path.parent.name != rule_id
    ):
        return None, "rule definition path does not match its scope and id"
    return path, ""


def _remove_project_assignment(
    rule_id: str, project_root: str
) -> tuple[bool, str]:
    project_config = _load_project_config(project_root)
    removed = project_config.get("rules", {}).pop(rule_id, None) is not None
    ok, error = _save_project_config(project_root, project_config)
    return removed and ok, "" if ok else error


def _remove_scoped_rule_state(
    path: Path,
    rule_id: str,
    *,
    remove_global: bool,
    project_roots: list[str],
) -> str:
    try:
        state = _load_scoped(path)
        if remove_global:
            state["global"].pop(rule_id, None)
        for root in project_roots:
            key = _project_key(root)
            values = state["projects"].get(key)
            if isinstance(values, dict):
                values.pop(rule_id, None)
                if not values:
                    state["projects"].pop(key, None)
        _save_scoped(path, state)
        return ""
    except OSError as exc:
        return str(exc)


def _usable_shared_definition(rule_id: str) -> Path | None:
    path = config.global_rules_dir() / rule_id / "rule.py"
    if not path.is_file():
        return None
    loaded = load_rule_file(path, "global")
    if len(loaded) != 1 or loaded[0].id != rule_id:
        return None
    return path


@_serialized_rule_mutation
def delete_rule_definition(
    rule_id: str,
    scope: str,
    project_root: str | None,
    expected_source_path: str,
    expected_source_hash: str,
    project_roots: list[str] | None = None,
    *,
    require_shared_fallback: bool = False,
) -> dict[str, Any]:
    path, error = _exact_definition_path(
        rule_id, scope, project_root, expected_source_path)
    if path is None:
        return {"ok": False, "error": error}
    exact_path = path
    if not expected_source_hash:
        return {
            "ok": False,
            "error": "exact source path and hash are required for deletion",
        }
    if not exact_path.is_file():
        return {"ok": False, "error": "rule definition no longer exists"}
    try:
        source = exact_path.read_bytes()
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    current_hash = _source_digest(source)
    if current_hash != expected_source_hash:
        return {
            "ok": False,
            "error": "rule source changed; reload and review it before deleting",
            "current_source_hash": current_hash,
        }
    loaded = load_rule_file(exact_path, scope)
    definition_count = rule_definition_count(exact_path)
    static_count = _static_rule_definition_count(source)
    decorator_count = len(re.findall(
        rb"(?m)^[ \t]*@(?:[A-Za-z_][A-Za-z0-9_]*\.)*"
        rb"rule(?:[ \t]*\(|[ \t]*$)",
        source,
    ))
    if (
        len(loaded) > 1
        or (definition_count is not None and definition_count > 1)
        or (static_count is not None and static_count > 1)
        or decorator_count > 1
    ):
        return {
            "ok": False,
            "error": (
                "this source file defines multiple rules; split them into "
                "one rule.py per ID before deleting"
            ),
        }
    if loaded and loaded[0].id != rule_id:
        return {
            "ok": False,
            "error": "rule source ID does not match its definition folder",
        }

    roots = [
        str(project_root or ""),
        *(str(root) for root in (project_roots or [])),
    ]
    known_projects = list(dict.fromkeys(root for root in roots if root))
    fallback_path = _usable_shared_definition(rule_id)
    has_shared_fallback = scope == "project" and fallback_path is not None
    if require_shared_fallback and not has_shared_fallback:
        return {
            "ok": False,
            "error": "a valid shared version is not available; project source was kept",
        }
    surviving_overrides = [
        root for root in known_projects
        if (
            config.project_rules_dir(root) / rule_id / "rule.py"
        ).expanduser().absolute().is_file()
        and not (
            scope == "project"
            and _project_key(root) == _project_key(project_root)
        )
    ]
    if require_shared_fallback:
        fallback_path = _usable_shared_definition(rule_id)
        if fallback_path is None:
            return {
                "ok": False,
                "error": (
                    "the shared version changed during revert; "
                    "project source was kept"
                ),
            }
        has_shared_fallback = True

    try:
        latest_hash = _source_digest(exact_path.read_bytes())
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    if latest_hash != current_hash:
        return {
            "ok": False,
            "error": "rule source changed during deletion; reload and try again",
            "current_source_hash": latest_hash,
        }

    warnings: list[str] = []
    try:
        exact_path.unlink()
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        revisions.remove_source(exact_path)
    except OSError as exc:
        warnings.append(f"active revision cleanup failed: {exc}")
    try:
        exact_path.parent.rmdir()
    except OSError:
        pass

    assignments_removed: list[str] = []
    if scope == "project":
        root = str(project_root or "")
        if not has_shared_fallback and root:
            removed, assignment_error = _remove_project_assignment(
                rule_id, root)
            if assignment_error:
                warnings.append(assignment_error)
            elif removed:
                assignments_removed.append(root)
            mute_error = _remove_scoped_rule_state(
                config.mutes_path(), rule_id,
                remove_global=False, project_roots=[root])
            if mute_error:
                warnings.append(mute_error)

    fallback = (
        {
            "scope": "global",
            "source_path": str(fallback_path.expanduser().resolve()),
        }
        if has_shared_fallback else None
    )
    return {
        "ok": True,
        "id": rule_id,
        "scope": scope,
        "source_path": str(exact_path),
        "source_hash": current_hash,
        "fallback": fallback,
        "assignments_removed": assignments_removed,
        "surviving_project_overrides": surviving_overrides,
        "assignment_state_preserved": scope == "global" or has_shared_fallback,
        "history_retained": True,
        "warnings": warnings,
    }


def delete_rule(
    rule_id: str,
    project_root: str | None,
    project_roots: list[str] | None = None,
    *,
    scope: str = "",
    expected_source_path: str = "",
    expected_source_hash: str = "",
) -> dict[str, Any]:
    """Compatibility name for callers that provide exact definition identity."""
    return delete_rule_definition(
        rule_id,
        scope,
        project_root,
        expected_source_path,
        expected_source_hash,
        project_roots,
    )


@_serialized_rule_mutation
def customize_for_project(rule_id: str, project_root: str) -> dict[str, Any]:
    global_info = get_rule(rule_id, None)
    if not global_info:
        return {"ok": False, "error": "shared rule not found"}
    result = save_rule(
        rule_id, global_info["source"], "project", project_root)
    if result.get("ok"):
        set_enabled(rule_id, True, project_root, global_info.get("name"))
    return result


@_serialized_rule_mutation
def revert_to_shared(
    rule_id: str,
    project_root: str,
    expected_source_path: str = "",
    expected_source_hash: str = "",
) -> dict[str, Any]:
    if not expected_source_path or not expected_source_hash:
        return {
            "ok": False,
            "error": "exact project source path and hash are required",
        }
    if _usable_shared_definition(rule_id) is None:
        return {
            "ok": False,
            "error": "a valid shared version is not available; project source was kept",
        }
    result = delete_rule_definition(
        rule_id,
        "project",
        project_root,
        expected_source_path,
        expected_source_hash,
        project_roots=[project_root],
        require_shared_fallback=True,
    )
    if not result.get("ok"):
        return result
    if not result.get("fallback"):
        return {
            **result,
            "ok": False,
            "error": "shared rule changed during revert",
        }
    return {
        **result,
        "reverted": result["source_path"],
        "assignment_preserved": True,
    }


@_serialized_rule_mutation
def promote_to_shared(rule_id: str, project_root: str) -> dict[str, Any]:
    project_info = get_rule(rule_id, project_root)
    if not project_info or project_info.get("scope") != "project":
        return {"ok": False, "error": "project rule not found"}
    target = config.global_rules_dir() / rule_id / "rule.py"
    if target.exists():
        return {"ok": False, "error": "a shared rule with this ID already exists"}
    result = save_rule(
        rule_id, project_info["source"], "global", None)
    if not result.get("ok"):
        return result
    old_path = Path(project_info["path"])
    active = revisions.active_info(rule_id, old_path)
    if active:
        revisions.migrate_source_path(rule_id, old_path, result["path"])
    old_path.unlink(missing_ok=True)
    try:
        old_path.parent.rmdir()
    except OSError:
        pass
    # Shared/My Rules are opt-in by default; retain this project explicitly.
    set_enabled(rule_id, False, None)
    set_enabled(rule_id, True, project_root, project_info.get("name"))
    return {
        **result,
        "promoted": True,
        "project_root": project_root,
    }


def attach_to_projects(
    rule_id: str, project_roots: list[str]
) -> dict[str, Any]:
    info = get_rule(rule_id, None)
    if not info:
        return {"ok": False, "error": "shared rule not found"}
    results = []
    for project_root in project_roots:
        results.append(set_enabled(
            rule_id, True, project_root, info.get("name")))
    return {
        "ok": all(item.get("ok") for item in results),
        "id": rule_id,
        "results": results,
    }


# --- conversion (prose -> draft) -------------------------------------------

def list_prose_rules(project_root: str) -> list[dict[str, Any]]:
    return [{"name": n, "prose": p} for n, p in scaffold.discover_prose_rules(project_root)]


def draft_from_prose(name: str, prose: str, scope: str,
                     project_root: str | None) -> dict[str, Any]:
    fname, text = scaffold.draft_rule_py(name, prose)
    rule_id = Path(fname).parent.name
    dest = _rules_dir(scope, project_root)
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / fname
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    set_enabled(rule_id, False, project_root if scope == "project" else None)
    return {"ok": True, "id": rule_id, "scope": scope, "path": str(target), "source": text}


# --- small JSON state helpers ----------------------------------------------

def _load(path: Path) -> dict[str, Any]:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(temporary, path)


# --- scoped state -----------------------------------------------------------

_STATE_VERSION = 2


def _project_key(project_root: str | None) -> str:
    return str(Path(project_root).expanduser()) if project_root else ""


def _load_scoped(path: Path) -> dict[str, Any]:
    """Load current scoped state."""
    raw = _load(path)
    if (
        raw.get("version") == _STATE_VERSION
        and isinstance(raw.get("global"), dict)
        and isinstance(raw.get("projects"), dict)
    ):
        return raw
    return {"version": _STATE_VERSION, "global": {}, "projects": {}}


def _save_scoped(path: Path, state: dict[str, Any]) -> None:
    state["version"] = _STATE_VERSION
    state.setdefault("global", {})
    state.setdefault("projects", {})
    _save(path, state)


# --- enable / disable (stops rule execution) -------------------------------

def _state_value(values: dict[str, Any], rule_id: str, default: Any = None):
    if rule_id in values:
        return True, values[rule_id]
    return False, default


def _load_project_config(project_root: str) -> dict[str, Any]:
    path = config.project_rules_config_path(project_root)
    if path.exists():
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict):
                value.setdefault("version", 1)
                if not isinstance(value.get("rules"), dict):
                    value["rules"] = {}
                return value
        except (OSError, json.JSONDecodeError):
            pass
    return {"version": 1, "rules": {}}


def _save_project_config(project_root: str, value: dict[str, Any]) -> tuple[bool, str]:
    path = config.project_rules_config_path(project_root)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
        return True, ""
    except OSError as exc:
        return False, str(exc)


def enabled_state(rule_id: str, project_root: str | None = None) -> dict[str, Any]:
    if not is_rule_id(rule_id):
        return {
            "effective_enabled": False,
            "global_default": False,
            "project_override": None,
            "assignment_origin": "invalid",
        }
    state = _load_scoped(config.rule_state_path())
    assignment_id = rule_id
    _found, global_value = _state_value(state["global"], rule_id, True)
    global_default = global_value is not False
    key = _project_key(project_root)
    if key:
        project_config = _load_project_config(key)
        config_entry = project_config.get("rules", {}).get(assignment_id)
        if isinstance(config_entry, dict) and "enabled" in config_entry:
            enabled = bool(config_entry["enabled"])
            return {
                "effective_enabled": enabled,
                "global_default": global_default,
                "project_override": enabled,
                "assignment_origin": "project",
            }
    return {
        "effective_enabled": global_default,
        "global_default": global_default,
        "project_override": None,
        "assignment_origin": "global_default",
    }


def is_enabled(rule_id: str, project_root: str | None = None) -> bool:
    return bool(enabled_state(rule_id, project_root)["effective_enabled"])


@_serialized_rule_mutation
def set_enabled(
    rule_id: str, enabled: bool, project_root: str | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    if not is_rule_id(rule_id):
        return {"ok": False, "error": "invalid rule id", "rule_id": rule_id}
    state = _load_scoped(config.rule_state_path())
    assignment_id = rule_id
    key = _project_key(project_root)
    if key:
        project_config = _load_project_config(key)
        assignments = project_config.setdefault("rules", {})
        global_default = enabled_state(rule_id, None)["global_default"]
        if bool(enabled) == global_default:
            assignments.pop(assignment_id, None)
            assignments.pop(rule_id, None)
        else:
            assignments[assignment_id] = {
                "enabled": bool(enabled),
                "name": name or "",
            }
        ok, error = _save_project_config(key, project_config)
        if not ok:
            return {
                "ok": False, "error": error, "rule_id": assignment_id,
                "project_root": key, "enabled": bool(enabled),
            }
    else:
        if enabled:
            state["global"].pop(rule_id, None)
        else:
            state["global"][rule_id] = False
        try:
            _save_scoped(config.rule_state_path(), state)
        except OSError as exc:
            return {
                "ok": False, "error": str(exc), "rule_id": assignment_id,
                "project_root": "", "enabled": bool(enabled),
            }
    return {
        "ok": True,
        "rule_id": assignment_id,
        "project_root": project_root or "",
        "enabled": bool(enabled),
        **enabled_state(assignment_id, project_root),
    }


@_serialized_rule_mutation
def reset_project_assignments(project_root: str) -> dict[str, Any]:
    value = _load_project_config(project_root)
    value["rules"] = {}
    ok, error = _save_project_config(project_root, value)
    return {"ok": ok, "error": error, "project_root": project_root}


@_serialized_rule_mutation
def set_project_assignments(
    project_root: str, assignments: dict[str, bool]
) -> dict[str, Any]:
    value = _load_project_config(project_root)
    value["rules"] = {
        rule_id: {"enabled": bool(enabled)}
        for rule_id, enabled in assignments.items()
        if is_rule_id(rule_id)
    }
    ok, error = _save_project_config(project_root, value)
    return {"ok": ok, "error": error, "project_root": project_root}


def rule_coverage(
    rule_id: str, project_roots: list[str]
) -> dict[str, Any]:
    global_default = enabled_state(rule_id, None)["global_default"]
    index = _load(config.rule_coverage_path())
    recorded = (
        (index.get("rules") or {}).get(rule_id, {})
        if isinstance(index.get("rules"), dict) else {}
    )
    indexed_projects = list(recorded.get("selected_projects") or [])
    roots = list(dict.fromkeys([*project_roots, *indexed_projects]))
    selected = [
        root for root in roots
        if is_enabled(rule_id, root)
    ]
    return {
        "mode": "all" if global_default else "selected",
        "all_projects": bool(global_default),
        "selected_projects": selected if not global_default else [],
    }


def deployment_coverage_draft(rule_id: str) -> dict[str, Any] | None:
    state = _load(config.rule_deployment_drafts_path())
    rules = state.get("rules")
    if not isinstance(rules, dict):
        return None
    value = rules.get(rule_id)
    return dict(value) if isinstance(value, dict) else None


@_serialized_rule_mutation
def save_deployment_coverage_draft(
    rule_id: str, coverage: dict[str, Any]
) -> dict[str, Any]:
    mode = str(coverage.get("mode", "selected"))
    if mode not in ("all", "selected"):
        return {"ok": False, "error": "invalid coverage mode"}
    state = _load(config.rule_deployment_drafts_path())
    rules = state.setdefault("rules", {})
    rules[rule_id] = {
        "mode": mode,
        "selected_projects": list(dict.fromkeys(
            str(root) for root in coverage.get("selected_projects", [])
            if root
        )),
        "confirmed": bool(coverage.get("confirmed")),
    }
    try:
        _save(config.rule_deployment_drafts_path(), state)
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "coverage": dict(rules[rule_id])}


@_serialized_rule_mutation
def clear_deployment_coverage_draft(rule_id: str) -> None:
    state = _load(config.rule_deployment_drafts_path())
    rules = state.get("rules")
    if isinstance(rules, dict) and rules.pop(rule_id, None) is not None:
        _save(config.rule_deployment_drafts_path(), state)


@_serialized_rule_mutation
def set_rule_coverage(
    rule_id: str,
    mode: str,
    selected_projects: list[str],
    project_roots: list[str],
    *,
    name: str = "",
) -> dict[str, Any]:
    """Atomically apply All Projects or explicit Selected Projects coverage."""
    if mode not in ("all", "selected"):
        return {"ok": False, "error": "coverage mode must be all or selected"}
    selected = {
        _project_key(root) for root in selected_projects if root
    }
    coverage_path = config.rule_coverage_path()
    old_coverage = _load(coverage_path)
    old_record = (
        (old_coverage.get("rules") or {}).get(rule_id, {})
        if isinstance(old_coverage.get("rules"), dict) else {}
    )
    roots = list(dict.fromkeys(
        _project_key(root)
        for root in [
            *project_roots,
            *selected_projects,
            *list(old_record.get("selected_projects") or []),
        ]
        if root
    ))
    state_path = config.rule_state_path()
    old_state = _load_scoped(state_path)
    new_state = json.loads(json.dumps(old_state))
    old_configs = {root: _load_project_config(root) for root in roots}
    new_configs = {
        root: json.loads(json.dumps(value))
        for root, value in old_configs.items()
    }
    if mode == "all":
        new_state["global"].pop(rule_id, None)
    else:
        new_state["global"][rule_id] = False
    for root, project_config in new_configs.items():
        assignments = project_config.setdefault("rules", {})
        if mode == "selected" and root in selected:
            assignments[rule_id] = {"enabled": True, "name": name}
        else:
            assignments.pop(rule_id, None)
    changed_roots = [
        root for root in roots
        if new_configs[root] != old_configs[root]
    ]
    try:
        _save_scoped(state_path, new_state)
        for root in changed_roots:
            project_config = new_configs[root]
            ok, error = _save_project_config(root, project_config)
            if not ok:
                raise OSError(error)
        new_coverage = json.loads(json.dumps(old_coverage))
        rules = new_coverage.setdefault("rules", {})
        rules[rule_id] = {
            "mode": mode,
            "selected_projects": sorted(selected) if mode == "selected" else [],
        }
        _save(coverage_path, new_coverage)
    except OSError as exc:
        try:
            _save_scoped(state_path, old_state)
            for root in changed_roots:
                _save_project_config(root, old_configs[root])
            _save(coverage_path, old_coverage)
        except OSError:
            pass
        return {"ok": False, "error": str(exc)}
    return {
        "ok": True,
        "rule_id": rule_id,
        **rule_coverage(rule_id, roots),
    }


# --- hide/show future findings (not evaluation/logging) ---------------------

def load_mutes() -> dict[str, Any]:
    return _load_scoped(config.mutes_path())


def _active_mute(value: Any, now: float) -> bool:
    if value is False:
        return False
    if value is None:
        return True
    try:
        return float(value) > now
    except (TypeError, ValueError):
        return False


def mute_info(rule_id: str, project_root: str | None = None) -> dict[str, Any]:
    state = load_mutes()
    now = time.time()
    key = _project_key(project_root)
    candidates: list[tuple[str, dict[str, Any], str]] = []
    if key:
        project = state["projects"].get(key, {})
        if not isinstance(project, dict):
            project = {}
        candidates.extend([
            ("project", project, rule_id),
            ("project", project, "*"),
        ])
    candidates.extend([
        ("global", state["global"], rule_id),
        ("global", state["global"], "*"),
    ])
    for scope, bucket, candidate in candidates:
        found, value = _state_value(bucket, candidate)
        if not found:
            continue
        # Explicit False is a project-level unmute override.
        if value is False:
            return {"muted": False, "until": None, "scope": scope}
        if _active_mute(value, now):
            return {"muted": True, "until": value, "scope": scope}
    return {"muted": False, "until": None, "scope": ""}


def is_muted(rule_id: str, project_root: str | None = None) -> bool:
    return bool(mute_info(rule_id, project_root)["muted"])


@_serialized_rule_mutation
def set_mute(
    rule_id: str, until: float | None, project_root: str | None = None
) -> dict[str, Any]:
    state = load_mutes()
    key = _project_key(project_root)
    if key:
        bucket = state["projects"].get(key)
        if not isinstance(bucket, dict):
            bucket = {}
            state["projects"][key] = bucket
    else:
        bucket = state["global"]
    bucket[rule_id] = until
    try:
        _save_scoped(config.mutes_path(), state)
    except OSError as exc:
        return {
            "ok": False, "error": str(exc), "rule_id": rule_id,
            "project_root": project_root or "", "until": until,
        }
    return {
        "ok": True,
        "rule_id": rule_id,
        "project_root": project_root or "",
        "until": until,
    }


@_serialized_rule_mutation
def clear_mute(
    rule_id: str, project_root: str | None = None
) -> dict[str, Any]:
    state = load_mutes()
    key = _project_key(project_root)
    if key:
        project = state["projects"].get(key)
        if not isinstance(project, dict):
            project = {}
            state["projects"][key] = project
        project.pop(rule_id, None)
        # If a global mute would still apply, keep an explicit local override.
        global_mute = mute_info(rule_id, None)["muted"]
        if global_mute:
            project[rule_id] = False
        if not project:
            state["projects"].pop(key, None)
    else:
        state["global"].pop(rule_id, None)
    try:
        _save_scoped(config.mutes_path(), state)
    except OSError as exc:
        return {
            "ok": False, "error": str(exc), "rule_id": rule_id,
            "project_root": project_root or "",
        }
    return {
        "ok": True,
        "rule_id": rule_id,
        "project_root": project_root or "",
    }


def monitoring_paused() -> bool:
    return bool(_load(config.monitoring_state_path()).get("paused", False))


def set_monitoring_paused(paused: bool) -> dict[str, Any]:
    try:
        _save(config.monitoring_state_path(), {
            "paused": bool(paused),
            "updated_at": time.time(),
        })
    except OSError as exc:
        return {"ok": False, "error": str(exc), "paused": bool(paused)}
    return {"ok": True, "paused": bool(paused)}


# --- per-project monitoring ------------------------------------------------

def project_enabled(project_root: str) -> bool:
    return _load(config.project_monitoring_path()).get(project_root, True) is not False


def set_project_enabled(project_root: str, enabled: bool) -> dict[str, Any]:
    state = _load(config.project_monitoring_path())
    if enabled:
        state.pop(project_root, None)
    else:
        state[project_root] = False
    try:
        _save(config.project_monitoring_path(), state)
    except OSError as exc:
        return {
            "ok": False, "error": str(exc),
            "project_root": project_root, "enabled": enabled,
        }
    return {"ok": True, "project_root": project_root, "enabled": enabled}
