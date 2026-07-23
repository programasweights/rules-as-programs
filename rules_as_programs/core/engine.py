"""The rule engine.

For each incoming :class:`Event`, the engine finds every rule whose ``on``
includes that event kind, builds a :class:`RuleContext` over the conversation's
evidence :class:`Ledger`, calls the rule's function, and turns a returned
message into a recorded :class:`Verdict` (and a per-project audit-log entry).

Judgment runs here, in the daemon, over observed evidence -- never inside the
agent. ``ctx`` is passed explicitly so rules are thread-safe under the daemon's
concurrent workers and trivially testable.
"""

from __future__ import annotations

import hashlib
import subprocess
import threading
from pathlib import Path
from typing import Any, Callable

from . import audit
from .events import Event
from .ledger import Ledger
from .rule import LoadedRule
from .store import Verdict, VerdictStore, finding_fingerprint
from ..paw_runtime import PawRuntime

MAX_INPUT_CHARS = 6000


class RuleContext:
    """The ``ctx`` handed to a rule function. Records a trace for the audit log."""

    def __init__(
        self, ledger: Ledger, runtime: PawRuntime,
        default_inputs: list[str] | None = None,
    ):
        self._ledger = ledger
        self._runtime = runtime
        self.project_root = ledger.project_root
        self.conversation_id = ledger.conversation_id
        self._default_inputs = list(default_inputs or [])
        self.trace: list[dict[str, Any]] = []

    # --- evidence access ------------------------------------------------
    def events(self, *kinds: str):
        wanted = set(kinds) if kinds else None
        return self._ledger.events(wanted)

    def latest(self, kind: str) -> str:
        return self._ledger.latest_text(kind)

    def input(self, max_events: int = 40) -> str:
        """Build standard evidence from the rule's declared ``inputs``."""
        latest = ["message"] if "message" in self._default_inputs else []
        include = [
            kind for kind in self._default_inputs if kind != "message"
        ]
        return self.evidence(
            latest=latest, include=include, max_events=max_events)

    def run(self, cmd: str) -> str:
        """Run a shell probe in the project root; records the output."""
        try:
            proc = subprocess.run(cmd, shell=True, cwd=self.project_root or None,
                                  capture_output=True, text=True, timeout=10)
            out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        except (subprocess.SubprocessError, OSError) as exc:
            out = f"(probe failed: {exc})"
        self.trace.append({"type": "run", "cmd": cmd, "output": out})
        return out

    def evidence(self, probes: dict[str, str] | None = None,
                 include: list[str] | None = None,
                 latest: list[str] | None = None,
                 max_events: int = 40) -> str:
        """Format a standard evidence block (## Probes / ## Latest / ## Recent)."""
        sections: list[str] = []
        probe_data: list[dict[str, Any]] = []
        latest_data: list[dict[str, Any]] = []
        event_data: list[dict[str, Any]] = []
        if probes:
            parts = []
            for name, cmd in probes.items():
                output = self.run(cmd)
                parts.append(f"[{name}]\n{output or '(no output)'}")
                probe_data.append({
                    "name": name,
                    "command": cmd,
                    "output": _snippet(output, 4000),
                })
            sections.append("## Probes\n" + "\n\n".join(parts))
        for kind in (latest or []):
            latest_text = self._ledger.latest_text(kind)
            if latest_text:
                sections.append(f"## Latest {kind}\n{latest_text}")
                latest_data.append({
                    "kind": kind,
                    "text": _snippet(latest_text, 4000),
                })
        if include:
            evs = self._ledger.events(set(include))[-max_events:]
            if evs:
                lines = [f"- ({e.kind}) {e.text()}" for e in evs]
                sections.append("## Recent activity\n" + "\n".join(lines))
                event_data = [{
                    "id": e.id,
                    "kind": e.kind,
                    "ts": e.ts,
                    "text": _snippet(e.text(), 2500),
                } for e in evs]
        text = "\n\n".join(sections).strip()
        if len(text) > MAX_INPUT_CHARS:
            text = "...\n" + text[-MAX_INPUT_CHARS:]
        text = text or "(no evidence gathered)"
        self.trace.append({
            "type": "evidence",
            "text": text,
            "probes": probe_data,
            "latest": latest_data,
            "events": event_data,
        })
        return text

    def paw(self, spec: str, compiler: str | None = None) -> Callable[[str], str]:
        """Return a local PAW judge ``fn(text) -> label``; records input/output."""
        def call(text: str) -> str:
            pid = self._runtime.program_id_for_spec(spec, compiler)
            label = (self._runtime.run(pid, text) if pid else None) or ""
            self.trace.append({"type": "paw", "input": text, "output": label})
            return label
        return call


class Engine:
    def __init__(
        self,
        runtime: PawRuntime,
        store: VerdictStore,
        rules_provider: Callable[[str], list[LoadedRule]],
        on_verdict: Callable[[Verdict], None] | None = None,
        is_muted: Callable[..., bool] | None = None,
        is_enabled: Callable[..., bool] | None = None,
    ):
        self.runtime = runtime
        self.store = store
        self.rules_provider = rules_provider
        self.on_verdict = on_verdict
        self.is_muted = is_muted
        self.is_enabled = is_enabled
        self._last_sig: dict[str, str] = {}
        self._lock = threading.Lock()

    # --- warming --------------------------------------------------------
    def warm(self, project_root: str) -> dict[str, bool]:
        results: dict[str, bool] = {}
        for rule in self.rules_provider(project_root):
            if not rule.spec:
                results[rule.id] = False
                continue
            pid = self.runtime.program_id_for_spec(rule.spec, None)
            results[rule.id] = bool(pid) and self.runtime.warm(pid)
        return results

    # --- evaluation -----------------------------------------------------
    @staticmethod
    def _parse_result(rule: LoadedRule, result: Any) -> tuple[str, str] | None:
        if result is None:
            return None
        if isinstance(result, str):
            msg = result.strip()
            return (rule.severity, msg) if msg else None
        if isinstance(result, (tuple, list)) and len(result) == 2:
            sev, msg = str(result[0]), str(result[1]).strip()
            return (sev, msg) if msg else None
        text = str(result).strip()
        return (rule.severity, text) if text else None

    def evaluate(
        self, rule: LoadedRule, ledger: Ledger, trigger_event: Event | None = None
    ) -> Verdict | None:
        ctx = RuleContext(ledger, self.runtime, rule.inputs)
        try:
            result = rule.fn(ctx)
        except Exception:
            return None  # a buggy rule must never crash the worker
        parsed = self._parse_result(rule, result)
        if parsed is None:
            return None
        severity, message = parsed
        suppressed = False
        if self.is_muted:
            try:
                suppressed = bool(self.is_muted(rule.id, ledger.project_root))
            except TypeError:  # pragma: no cover - upgrade compatibility
                suppressed = bool(self.is_muted(rule.id))

        rule_source = ""
        if rule.source_path:
            try:
                rule_source = Path(rule.source_path).read_text(encoding="utf-8")
            except OSError:
                rule_source = ""
        rule_hash = (
            hashlib.sha256(rule_source.encode("utf-8")).hexdigest()
            if rule_source else ""
        )
        sig = (
            f"{severity}|{message}|source={rule_hash}|"
            f"suppressed={int(suppressed)}"
        )
        dedup_key = f"{ledger.conversation_id}:{rule.id}"
        with self._lock:
            if self._last_sig.get(dedup_key) == sig:
                return None
            self._last_sig[dedup_key] = sig

        verdict = Verdict(
            rule_id=rule.id, rule_title=rule.title, severity=severity,
            message=message, conversation_id=ledger.conversation_id,
            project_root=ledger.project_root, label=_trace_label(ctx.trace),
            evidence=_snippet(_trace_input(ctx.trace)),
            fuzzy=bool(rule.spec),
            fingerprint=finding_fingerprint(
                ledger.project_root, rule.id, message, rule_hash),
            trigger_event_id=trigger_event.id if trigger_event else "",
            trigger_kind=trigger_event.kind if trigger_event else "",
            source_hash=rule_hash,
            suppressed=suppressed,
            suppression_reason="rule muted" if suppressed else "",
        )
        verdict.id = self.store.record(verdict)
        audit.log_violation(
            ledger.project_root,
            verdict.id,
            rule.id,
            rule.title,
            severity,
            message,
            ctx.trace,
            conversation_id=ledger.conversation_id,
            trigger_event_id=verdict.trigger_event_id,
            trigger_kind=verdict.trigger_kind,
            fingerprint=verdict.fingerprint,
            suppressed=verdict.suppressed,
            suppression_reason=verdict.suppression_reason,
            ts=verdict.ts,
            rule_scope=rule.scope,
            rule_path=rule.source_path,
            rule_source_hash=rule_hash,
            rule_source=rule_source,
        )
        if self.on_verdict:
            try:
                self.on_verdict(verdict)
            except Exception:
                pass
        return verdict

    def on_event(self, event: Event, ledger: Ledger) -> list[Verdict]:
        out: list[Verdict] = []
        for rule in self.rules_provider(event.project_root):
            if rule.channel != "finding":
                continue
            if event.kind not in rule.on:
                continue
            if self.is_enabled:
                try:
                    enabled = self.is_enabled(rule.id, event.project_root)
                except TypeError:  # pragma: no cover - upgrade compatibility
                    enabled = self.is_enabled(rule.id)
                if not enabled:
                    continue
            v = self.evaluate(rule, ledger, event)
            if v:
                out.append(v)
        return out


def _trace_input(trace: list[dict[str, Any]]) -> str:
    for item in reversed(trace):
        if item.get("type") == "evidence":
            return item.get("text", "")
        if item.get("type") == "paw":
            return item.get("input", "")
    return ""


def _trace_label(trace: list[dict[str, Any]]) -> str:
    for item in reversed(trace):
        if item.get("type") == "paw":
            return str(item.get("output", "")).strip()
    return ""


def _snippet(text: str, limit: int = 400) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit] + " ..."
