"""Scaffolding: ship built-in rules into a scope, and discover/convert a
project's existing prose rules into Python rule drafts.

Conversion is intentionally conservative: it produces a *draft* ``.py`` rule
(left disabled) whose ``SPEC`` embeds the original prose and a SATISFIED/VIOLATED
contract. The user (or the Cursor agent, per AGENTS.md) then refines the spec and
examples, runs ``rap rules test``, and enables it.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from . import config

BUILTIN_DIR = Path(__file__).parent / "builtin_rules"


def builtin_rules() -> list[Path]:
    return sorted(BUILTIN_DIR.glob("*.py"))


def builtin_ids() -> list[str]:
    return [p.stem for p in builtin_rules()]


def rules_dir_for(scope: str, project_root: str | None) -> Path:
    if scope == "global":
        return config.global_rules_dir()
    return config.project_rules_dir(project_root or Path.cwd())


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
        legacy_target = dest / src.name
        if (target.exists() or legacy_target.exists()) and not overwrite:
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
    legacy_target = dest / src.name
    if (target.exists() or legacy_target.exists()) and not overwrite:
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
    """Return (name, text) for existing Cursor/agent rule sources."""
    root = Path(project_root)
    found: list[tuple[str, str]] = []
    candidates: list[Path] = []
    rules_dir = root / ".cursor" / "rules"
    if rules_dir.exists():
        candidates += sorted(rules_dir.glob("*.mdc"))
        candidates += sorted(rules_dir.glob("*.md"))
    for name in ("AGENTS.md", ".cursorrules"):
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

    rule_id = str(uuid.uuid4())
    title = name.replace("-", " ").replace("_", " ").strip().title()
    prose_compact = " ".join(prose.split())
    if len(prose_compact) > 600:
        prose_compact = prose_compact[:600] + " ..."
    src = rules_api.generate_managed_fuzzy_source(
        rule_id,
        title,
        f"Decide whether the agent violated this project rule: {prose_compact}",
        f"Project rule may be violated: {title}.",
        severity="warn",
        on=["message", "session_stop"],
        inputs=["message", "thought", "shell_exec", "file_edit", "tool_result"],
        cases=[],
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
