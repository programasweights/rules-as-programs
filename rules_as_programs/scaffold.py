"""Scaffolding: ship built-in rules into a scope, and discover/convert a
project's existing prose rules into Python rule drafts.

Conversion is intentionally conservative: it produces a *draft* ``.py`` rule
(left disabled) whose ``SPEC`` embeds the original prose and a SATISFIED/VIOLATED
contract. The user (or Codex, per AGENTS.md) then refines the spec and
examples, runs ``rap rules test``, and enables it.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from . import config
from .core.rule import new_rule_id

BUILTIN_DIR = Path(__file__).parent / "builtin_rules"

# Old Cursor trigger -> (Codex trigger, old default pointer, Codex override).
# An empty Codex override means to use that trigger's new documented default.
LEGACY_TRIGGER_MIGRATIONS = {
    "afterAgentResponse": ("Stop", "/text", ""),
    "afterAgentThought": ("Stop", "/text", ""),
    "beforeSubmitPrompt": ("UserPromptSubmit", "/prompt", ""),
    "preToolUse": ("PreToolUse", "/tool_name", ""),
    "postToolUse": ("PostToolUse", "/tool_output", ""),
    "postToolUseFailure": ("PostToolUse", "/error_message", ""),
    "beforeShellExecution": ("PreToolUse", "/command", ""),
    "afterShellExecution": ("PreToolUse", "/command", ""),
    "afterFileEdit": ("PostToolUse", "/file_path", "/tool_input"),
    "beforeReadFile": ("PreToolUse", "/file_path", ""),
    "beforeMCPExecution": ("PreToolUse", "/tool_name", ""),
    "afterMCPExecution": ("PostToolUse", "/result_json", ""),
    "subagentStart": ("SubagentStart", "/task", ""),
    "subagentStop": ("SubagentStop", "/summary", ""),
    "preCompact": ("PreCompact", "/trigger", ""),
    "sessionStart": ("SessionStart", "/composer_mode", ""),
    "sessionEnd": ("SessionEnd", "/final_status", ""),
    "stop": ("Stop", "/status", ""),
    "beforeTabFileRead": ("PreToolUse", "/file_path", ""),
    "afterTabFileEdit": ("PostToolUse", "/file_path", "/tool_input"),
}


def builtin_rules() -> list[Path]:
    return sorted(BUILTIN_DIR.glob("*.py"))


def builtin_ids() -> list[str]:
    return [p.stem for p in builtin_rules()]


def prune_obsolete_managed_rules(
    project_roots: list[str] | None = None,
) -> list[str]:
    """Remove pre-V4 managed rules during development-schema replacement."""
    roots = [config.global_rules_dir()]
    roots.extend(
        config.project_rules_dir(project)
        for project in (project_roots or []))
    removed = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.glob("*/rule.py"):
            try:
                source = path.read_text(encoding="utf-8")
            except OSError:
                continue
            if not any(
                marker in source
                for marker in (
                    "# RAP_MANAGED_FUZZY_V2",
                    "# RAP_MANAGED_FUZZY_V3",
                )
            ):
                continue
            shutil.rmtree(path.parent, ignore_errors=True)
            removed.append(str(path))
    return removed


def rules_dir_for(scope: str, project_root: str | None) -> Path:
    if scope == "global":
        return config.global_rules_dir()
    return config.project_rules_dir(project_root or Path.cwd())


def _copy_missing_tree(source: Path, destination: Path) -> int:
    if not source.exists():
        return 0
    copied = 0
    for path in source.rglob("*"):
        if path.is_symlink():
            continue
        relative = path.relative_to(source)
        target = destination / relative
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif path.is_file() and not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            copied += 1
    return copied


def _migrate_rule_triggers(directory: Path) -> int:
    from . import rules_api

    migrated = 0
    for path in directory.glob("*/rule.py") if directory.exists() else ():
        try:
            source = path.read_text(encoding="utf-8")
        except OSError:
            continue
        projection = rules_api.source_projection(source)
        old_trigger = str(projection.get("trigger", ""))
        mapping = LEGACY_TRIGGER_MIGRATIONS.get(old_trigger)
        if not projection.get("ok") or mapping is None:
            continue
        new_trigger, old_default_pointer, new_default_override = mapping
        pointer = str(projection.get("input_pointer", ""))
        new_pointer = (
            new_default_override
            if not pointer or pointer == old_default_pointer
            else pointer
        )
        ok, updated, _error = rules_api.patch_source_projection(
            source,
            trigger=new_trigger,
            input_pointer=new_pointer,
            function_source=str(projection.get("function_source", "")),
        )
        if not ok or updated == source:
            continue
        path.write_text(updated, encoding="utf-8")
        migrated += 1
    return migrated


def migrate_legacy_cursor_state(
    scope: str,
    project_root: str | None,
) -> list[str]:
    """Copy missing pre-Codex RAP state and translate old trigger metadata.

    The legacy tree is deliberately retained as a rollback copy. Existing Codex
    files always win, so rerunning ``rap init`` cannot overwrite newer work.
    """
    notes: list[str] = []
    scopes = ["global"]
    if scope == "project":
        scopes.append("project")
    for current_scope in scopes:
        if current_scope == "global":
            source = config.legacy_rules_dir("global")
            destination = config.global_rules_dir()
        else:
            source = config.legacy_project_state_dir(project_root or Path.cwd())
            destination = Path(project_root or Path.cwd()) / ".codex" / config.APP_NAME
        copied = _copy_missing_tree(source, destination)
        if copied:
            notes.append(
                f"copied {copied} legacy file{'s' if copied != 1 else ''} "
                f"from {source}"
            )
        rules_directory = (
            destination if current_scope == "global"
            else destination / "rules"
        )
        migrated = _migrate_rule_triggers(rules_directory)
        if migrated:
            notes.append(
                f"updated {migrated} legacy rule trigger"
                f"{'s' if migrated != 1 else ''} for Codex"
            )
    return notes


def install_builtins(scope: str, project_root: str | None, overwrite: bool = False) -> list[str]:
    from . import rules_api
    from .core.rule import load_rule_file

    dest = rules_dir_for(scope, project_root)
    dest.mkdir(parents=True, exist_ok=True)
    notes: list[str] = []
    for src in builtin_rules():
        loaded = load_rule_file(src, "builtin")
        if not loaded:
            notes.append(f"could not load {src.name}")
            continue
        rule = loaded[0]
        target = dest / rule.id / "rule.py"
        if target.exists() and not overwrite:
            notes.append(f"kept existing {target.name}")
            continue
        source = src.read_text(encoding="utf-8")
        ok, source, error = rules_api.patch_rule_identity(
            source, rule.id, rule.title)
        if not ok:
            notes.append(f"could not prepare {src.name}: {error}")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
        notes.append(f"installed {rule.title}")
    return notes


def add_builtin(
    rule_id: str,
    scope: str,
    project_root: str | None,
    overwrite: bool = False,
) -> Path | None:
    from . import rules_api
    from .core.rule import load_rule_file

    src = BUILTIN_DIR / f"{rule_id}.py"
    if not src.exists():
        return None
    dest = rules_dir_for(scope, project_root)
    dest.mkdir(parents=True, exist_ok=True)
    loaded = load_rule_file(src, "builtin")
    if not loaded:
        return None
    rule = loaded[0]
    target = dest / rule.id / "rule.py"
    if target.exists() and not overwrite:
        return None
    source = src.read_text(encoding="utf-8")
    ok, source, _error = rules_api.patch_rule_identity(
        source, rule.id, rule.title)
    if not ok:
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return target


# --- discover existing prose rules -----------------------------------------

def discover_prose_rules(project_root: str) -> list[tuple[str, str]]:
    """Return prose agent instructions that can seed independent rules."""
    root = Path(project_root)
    found: list[tuple[str, str]] = []
    candidates: list[Path] = []
    rules_dir = root / ".cursor" / "rules"
    if rules_dir.exists():
        candidates += sorted(rules_dir.glob("*.mdc"))
        candidates += sorted(rules_dir.glob("*.md"))
    for name in ("AGENTS.md", "AGENTS.override.md", ".cursorrules"):
        p = root / name
        if p.exists():
            candidates.append(p)
    for p in candidates:
        try:
            text = p.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text:
            found.append((p.stem if p.suffix else p.name, text))
    return found


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "rule"


def draft_rule_py(name: str, prose: str) -> tuple[str, str]:
    """Build (filename, python_source) for a draft Python rule from prose."""
    from . import rules_api

    rule_id = new_rule_id()
    title = name.replace("-", " ").replace("_", " ").strip().title()
    prose_compact = " ".join(prose.split())
    if len(prose_compact) > 600:
        prose_compact = prose_compact[:600] + " ..."
    src = rules_api.generate_managed_fuzzy_source(
        rule_id,
        title,
        (
            f"Decide whether the agent violated this project rule: "
            f"{prose_compact}\n\n"
            "Return OK when the rule was not violated.\n"
            "Return WARNING when the rule was violated."
        ),
        trigger="Stop",
    )
    return f"{rule_id}/rule.py", src


def convert_prose_rules(project_root: str, scope: str) -> list[str]:
    """Draft .py rules from prose sources; new drafts are created disabled."""
    from . import rules_api  # local import to avoid a cycle at module load

    dest = rules_dir_for(scope, project_root)
    dest.mkdir(parents=True, exist_ok=True)
    notes: list[str] = []
    for name, prose in discover_prose_rules(project_root):
        fname, text = draft_rule_py(name, prose)
        target = dest / fname
        if target.exists():
            notes.append(f"skipped {fname} (already exists)")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        rules_api.set_enabled(
            target.parent.name,
            False,
            project_root if scope == "project" else None,
        )  # drafts start disabled
        notes.append(f"drafted {fname} (disabled; review + `rap rules test {target.stem}`)")
    if not notes:
        notes.append("no existing prose rules found to convert")
    return notes
