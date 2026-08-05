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
import threading
from pathlib import Path
from typing import Any, Callable

from . import audit
from .events import Event
from .ledger import Ledger
from .rule import LoadedRule
from .store import Verdict, VerdictStore, finding_fingerprint
from .triggers import InputPointerError, TRIGGERS, extract_input
from ..paw_runtime import PawRuntime

SEVERITY_ALIASES = {
    "info": "info",
    "warning": "warn",
    "warn": "warn",
    "critical": "critical",
}


class PawDecision(str):
    """String-compatible PAW result carrying its originating trace index."""

    def __new__(cls, value: str, trace_index: int):
        instance = str.__new__(cls, value)
        instance.trace_index = trace_index
        return instance


class FindingResult(tuple):
    """Strict severity result linked to its trace entry."""

    def __new__(cls, severity: str, trace_index: int):
        instance = tuple.__new__(cls, (severity,))
        instance.trace_index = trace_index
        return instance


class RuleContext:
    """The ``ctx`` handed to a rule function. Records a trace for the audit log."""

    def __init__(
        self, ledger: Ledger, runtime: PawRuntime,
        default_compiler: str | None = None,
        through_seq: int | None = None,
        input_text: str = "",
    ):
        self._ledger = ledger
        self._runtime = runtime
        self.project_root = ledger.project_root
        self.conversation_id = ledger.conversation_id
        self._default_compiler = default_compiler
        self.through_seq = through_seq
        self._input = input_text
        self.trace: list[dict[str, Any]] = []

    @property
    def input(self) -> str:
        return self._input

    def paw(self, spec: str, compiler: str | None = None) -> Callable[[str], str]:
        """Return a local PAW judge ``fn(text) -> label``; records input/output."""
        def call(text: str) -> str:
            if text != self._input:
                raise ValueError(
                    "PAW input must be the exact trigger field ctx.input")
            resolved_compiler = (
                compiler if compiler is not None else self._default_compiler)
            pid = self._runtime.program_id_for_spec(spec, resolved_compiler)
            label = (self._runtime.run(pid, text) if pid else None) or ""
            trace_index = len(self.trace)
            self.trace.append({"type": "paw", "input": text, "output": label})
            return PawDecision(str(label), trace_index)
        return call

    def result(self, level: str):
        """Return one strict severity result, or ``None`` for OK."""
        label = str(level or "").strip().upper()
        if label == "OK":
            return None
        severity = {
            "INFO": "info",
            "WARNING": "warn",
            "CRITICAL": "critical",
        }.get(label)
        if severity is None:
            raise ValueError(
                f"invalid fuzzy severity {label!r}; expected "
                "OK, INFO, WARNING, or CRITICAL")
        trace_index = len(self.trace)
        self.trace.append({
            "type": "finding_result",
            "level": label,
            "paw_trace_index": getattr(level, "trace_index", None),
        })
        return FindingResult(severity, trace_index)


class Engine:
    def __init__(
        self,
        runtime: PawRuntime,
        store: VerdictStore,
        rules_provider: Callable[[str], list[LoadedRule]],
        on_verdict: Callable[[Verdict], None] | None = None,
        on_error: Callable[[LoadedRule, str, str], None] | None = None,
        on_success: Callable[[LoadedRule, str], None] | None = None,
        is_muted: Callable[..., bool] | None = None,
        is_enabled: Callable[..., bool] | None = None,
    ):
        self.runtime = runtime
        self.store = store
        self.rules_provider = rules_provider
        self.on_verdict = on_verdict
        self.on_error = on_error
        self.on_success = on_success
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
    def _parse_result(_rule: LoadedRule, result: Any) -> str | None:
        if result is None:
            return None
        if not isinstance(result, FindingResult):
            raise ValueError(
                "finding rules must return ctx.result(INFO|WARNING|CRITICAL)")
        severity = SEVERITY_ALIASES.get(str(result[0]).lower())
        if not severity:
            raise ValueError(f"invalid rule severity {result[0]!r}")
        return severity

    def evaluate(
        self, rule: LoadedRule, ledger: Ledger, trigger_event: Event | None = None
    ) -> Verdict | None:
        initial_events = ledger.events()
        trigger_index = next(
            (
                index for index, event in enumerate(initial_events)
                if trigger_event is not None and event.id == trigger_event.id
            ),
            -1,
        )
        through_seq = (
            trigger_index + 1 if trigger_index >= 0 else len(initial_events))
        hook_name = (
            trigger_event.hook_name if trigger_event else rule.trigger)
        raw_payload = (
            trigger_event.raw_payload if trigger_event else {})
        try:
            input_text, input_pointer, input_type, input_overridden = (
                extract_input(
                    rule.trigger or hook_name,
                    raw_payload,
                    rule.input_pointer,
                )
            )
            input_bytes = len(input_text.encode("utf-8"))
            if input_bytes > rule.max_input_bytes:
                raise InputPointerError(
                    "input too large: "
                    f"{input_bytes} bytes exceeds {rule.max_input_bytes}")
        except InputPointerError as exc:
            if self.on_error:
                self.on_error(rule, ledger.project_root, str(exc))
            return None
        ctx = RuleContext(
            ledger, self.runtime, rule.compiler or None, through_seq, input_text)
        try:
            result = rule.fn(ctx)
            parsed = self._parse_result(rule, result)
        except Exception as exc:
            if self.on_error:
                try:
                    self.on_error(rule, ledger.project_root, str(exc))
                except Exception:
                    pass
            return None  # a buggy rule must never crash the worker
        if self.on_success:
            try:
                self.on_success(rule, ledger.project_root)
            except Exception:
                pass
        if parsed is None:
            return None
        severity = parsed
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
        sig = f"{severity}|source={rule_hash}|suppressed={int(suppressed)}"
        dedup_key = f"{ledger.conversation_id}:{rule.id}"
        with self._lock:
            if self._last_sig.get(dedup_key) == sig:
                return None
            self._last_sig[dedup_key] = sig

        evaluation = _evaluation_snapshot(
            rule,
            severity=severity,
            ledger=ledger,
            trigger_event=trigger_event,
            context_through_seq=through_seq,
            rule_source=rule_source,
            rule_source_hash=rule_hash,
            input_text=input_text,
            input_pointer=input_pointer,
            input_type=input_type,
            input_overridden=input_overridden,
        )
        verdict = Verdict(
            rule_id=rule.id, rule_title=rule.title, severity=severity,
            conversation_id=ledger.conversation_id,
            project_root=ledger.project_root, evaluation=evaluation,
            fingerprint=finding_fingerprint(
                ledger.project_root, rule.id, severity, rule_hash),
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
            "",
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
            evaluation=evaluation,
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
            if not rule.trigger or event.hook_name != rule.trigger:
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


def _evaluation_snapshot(
    rule: LoadedRule,
    *,
    severity: str,
    ledger: Ledger,
    trigger_event: Event | None,
    context_through_seq: int,
    rule_source: str,
    rule_source_hash: str,
    input_text: str,
    input_pointer: str,
    input_type: str,
    input_overridden: bool,
) -> dict[str, Any]:
    input_bytes = input_text.encode("utf-8")
    events = ledger.events()
    trigger_index = next(
        (
            index for index, event in enumerate(events)
            if trigger_event is not None and event.id == trigger_event.id
        ),
        -1,
    )
    through_seq = min(len(events), max(0, int(context_through_seq)))
    return {
        "schema_version": 4,
        "rule": {
            "id": rule.id,
            "name": rule.title,
            "compiler": rule.compiler,
            "program_id": rule.program_id,
            "source_hash": rule_source_hash,
            "source": rule_source,
        },
        "input": {
            "text": input_text,
            "sha256": hashlib.sha256(input_bytes).hexdigest(),
            "char_count": len(input_text),
            "byte_count": len(input_bytes),
            "format": "json" if input_type in ("object", "array") else "plain",
            "json_pointer": input_pointer,
            "pointer_source": "override" if input_overridden else "default",
            "value_type": input_type,
            "event_ids": [trigger_event.id] if trigger_event else [],
        },
        "severity": severity,
        "trigger": {
            "event_id": trigger_event.id if trigger_event else "",
            "kind": trigger_event.kind if trigger_event else "",
            "hook": trigger_event.hook_name if trigger_event else rule.trigger,
            "seq": trigger_index + 1 if trigger_index >= 0 else None,
            "included_in_input": True,
            "event": (
                {
                    **trigger_event.to_dict(),
                    "text": trigger_event.text(),
                }
                if trigger_event else None
            ),
        },
        "context_through_seq": through_seq,
    }
