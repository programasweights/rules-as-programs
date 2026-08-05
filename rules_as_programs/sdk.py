"""Public rule-authoring API -- deliberately tiny and class-free.

A rule is ONE decorated function per file:

    from rules_as_programs import rule

    SPEC = '''Decide ...\nReturn ONLY one of: OK, INFO, WARNING, CRITICAL\n...'''

    @rule(severity="warn", on=["session_stop"],
          inputs=["file_edit", "shell_exec"], spec=SPEC)
    def github_sync(ctx):
        "Use GitHub to synchronize code."          # title (from docstring)
        decision = ctx.paw(SPEC)(ctx.input())
        return ctx.result(decision)

Finding rules return ``ctx.result("OK"|"INFO"|"WARNING"|"CRITICAL")``. ``OK``
returns ``None``; the other labels create one strict severity result.

The ``ctx`` argument is handed to the function by the engine (the author never
constructs it). ``inputs=[...]`` configures ``ctx.input()``. It also exposes:
``ctx.evidence(...)``, ``ctx.events(*kinds)``,
``ctx.latest(kind)``, ``ctx.run(cmd)``, ``ctx.paw(spec, compiler=None)``, and
``ctx.project_root`` / ``ctx.conversation_id``.

PAW is the default judge and runs locally (private, offline after first
compile). A rule can equally be plain Python -- no PAW at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from . import paw_runtime

SEVERITIES = ("info", "warn", "critical")

# Attribute stamped on a decorated function so the loader can find it.
RULE_ATTR = "_rap_rule"


@dataclass
class RuleDef:
    """Internal metadata attached to a decorated rule function."""
    id: str
    title: str
    severity: str
    on: list[str]
    inputs: list[str]
    probes: dict[str, str]
    channel: str
    fn: Callable
    spec: str | None = None
    examples: list[tuple[str, str]] = field(default_factory=list)


def rule(*, severity: str = "warn", on: list[str] | None = None,
         inputs: list[str] | None = None,
         probes: dict[str, str] | None = None,
         channel: str = "finding",
         id: str | None = None, name: str | None = None,
         title: str | None = None,
         spec: str | None = None,
         examples: list[tuple[str, str]] | None = None):
    """Decorator that turns a function into a rule.

    New managed rules persist an immutable 16-character ``id`` and mutable
    ``name``. Legacy files are migrated by the loader/editor. ``title`` is
    retained as a compatibility alias for ``name``. ``inputs`` configures ``ctx.input()``.
    ``spec``/``examples`` are optional PAW metadata; Input/Output cases embedded
    directly in ``spec`` are preferred over a duplicate examples list.
    """
    def deco(fn: Callable) -> Callable:
        # New managed rules persist a compact ``id`` in source. Legacy rules often
        # omit it or use a readable slug; the loader migrates those safely.
        rid = id or ""
        doc = (fn.__doc__ or "").strip()
        ttl = name or title or (
            doc.splitlines()[0].strip() if doc
            else fn.__name__.replace("_", " ").title()
        )
        setattr(fn, RULE_ATTR, RuleDef(
            id=rid, title=ttl, severity=severity, on=list(on or []),
            inputs=list(inputs or []),
            probes=dict(probes or {}),
            channel=channel,
            fn=fn, spec=spec, examples=list(examples or []),
        ))
        return fn
    return deco


def paw_function(spec: str, compiler: str | None = None) -> Callable[[str], str]:
    """Return a callable ``fn(text) -> label`` backed by a PAW program.

    Compile-cached and warmed via the shared local runtime; lazy on first call.
    Returns "" on any failure so rules degrade gracefully. Most rules should
    prefer ``ctx.paw(spec)`` (identical, but also records the audit trace).
    """
    rt = paw_runtime.shared()
    holder: dict[str, str | None] = {"pid": None, "resolved": None}

    def call(text: str) -> str:
        if not holder["resolved"]:
            holder["pid"] = rt.program_id_for_spec(spec, compiler)
            holder["resolved"] = "yes"
        pid = holder["pid"]
        if not pid:
            return ""
        return rt.run(pid, text) or ""

    return call
