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
import json
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
    """Tuple-compatible finding result linked to its trace entry."""

    def __new__(
        cls, severity: str, message: str, trace_index: int
    ):
        instance = tuple.__new__(cls, (severity, message))
        instance.trace_index = trace_index
        return instance


class RuleContext:
    """The ``ctx`` handed to a rule function. Records a trace for the audit log."""

    def __init__(
        self, ledger: Ledger, runtime: PawRuntime,
        default_inputs: list[str] | None = None,
        default_probes: dict[str, str] | None = None,
        default_compiler: str | None = None,
        through_seq: int | None = None,
    ):
        self._ledger = ledger
        self._runtime = runtime
        self.project_root = ledger.project_root
        self.conversation_id = ledger.conversation_id
        self._default_inputs = list(default_inputs or [])
        self._default_probes = dict(default_probes or {})
        self._default_compiler = default_compiler
        self.through_seq = through_seq
        self.trace: list[dict[str, Any]] = []

    # --- evidence access ------------------------------------------------
    def events(self, *kinds: str):
        wanted = set(kinds) if kinds else None
        events = self._ledger.events()
        if self.through_seq is not None:
            events = events[:self.through_seq]
        return (
            [event for event in events if event.kind in wanted]
            if wanted is not None else events
        )

    def latest(self, kind: str) -> str:
        events = self.events(kind)
        return events[-1].text() if events else ""

    def input(self, max_events: int = 40) -> str:
        """Build standard evidence from the rule's declared ``inputs``."""
        latest = ["message"] if "message" in self._default_inputs else []
        include = [
            kind for kind in self._default_inputs if kind != "message"
        ]
        return self.evidence(
            probes=self._default_probes,
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
            latest_events = self.events(kind)
            latest_event = latest_events[-1] if latest_events else None
            latest_text = latest_event.text() if latest_event else ""
            if latest_text:
                sections.append(f"## Latest {kind}\n{latest_text}")
                latest_data.append({
                    "id": latest_event.id,
                    "kind": kind,
                    "ts": latest_event.ts,
                    "text": _snippet(latest_text, 4000),
                    "_needle": f"## Latest {kind}\n{latest_text}",
                })
        if include:
            evs = [
                event for event in self.events()
                if event.kind in set(include)
            ][-max_events:]
            if evs:
                lines = [f"- ({e.kind}) {e.text()}" for e in evs]
                sections.append("## Recent activity\n" + "\n".join(lines))
                event_data = [{
                    "id": e.id,
                    "kind": e.kind,
                    "ts": e.ts,
                    "text": _snippet(e.text(), 2500),
                    "_needle": line,
                } for e, line in zip(evs, lines)]
        full_text = "\n\n".join(sections).strip()
        cursor = 0
        for item in [*latest_data, *event_data]:
            needle = str(item.pop("_needle", ""))
            start = full_text.find(needle, cursor)
            if start >= 0:
                item["_full_input_span"] = [start, start + len(needle)]
                cursor = start + len(needle)
        trim_start = max(0, len(full_text) - MAX_INPUT_CHARS)
        prefix_length = 4 if trim_start else 0
        for item in [*latest_data, *event_data]:
            span = item.pop("_full_input_span", None)
            if span and span[1] > trim_start:
                item["input_span"] = [
                    max(prefix_length, prefix_length + span[0] - trim_start),
                    prefix_length + span[1] - trim_start,
                ]
                item["input_inclusion"] = (
                    "full" if span[0] >= trim_start else "partial")
        text = full_text
        if trim_start:
            text = "...\n" + full_text[trim_start:]
        text = text or "(no evidence gathered)"
        trace_index = len(self.trace)
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
            resolved_compiler = (
                compiler if compiler is not None else self._default_compiler)
            pid = self._runtime.program_id_for_spec(spec, resolved_compiler)
            label = (self._runtime.run(pid, text) if pid else None) or ""
            trace_index = len(self.trace)
            self.trace.append({"type": "paw", "input": text, "output": label})
            return PawDecision(str(label), trace_index)
        return call

    def finding(self, level: str, message: str):
        """Map a managed fuzzy output label to an engine finding result."""
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
            "message": str(message).strip(),
            "paw_trace_index": getattr(level, "trace_index", None),
        })
        return FindingResult(
            severity, str(message).strip(), trace_index)


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
    def _parse_result(rule: LoadedRule, result: Any) -> tuple[str, str] | None:
        if result is None:
            return None
        if isinstance(result, str):
            msg = result.strip()
            severity = SEVERITY_ALIASES.get(rule.severity.lower())
            if not severity:
                raise ValueError(f"invalid rule severity {rule.severity!r}")
            return (severity, msg) if msg else None
        if isinstance(result, (tuple, list)) and len(result) == 2:
            raw_severity, msg = str(result[0]).strip().lower(), str(result[1]).strip()
            severity = SEVERITY_ALIASES.get(raw_severity)
            if not severity:
                raise ValueError(f"invalid rule severity {result[0]!r}")
            return (severity, msg) if msg else None
        text = str(result).strip()
        severity = SEVERITY_ALIASES.get(rule.severity.lower())
        if not severity:
            raise ValueError(f"invalid rule severity {rule.severity!r}")
        return (severity, text) if text else None

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
        ctx = RuleContext(
            ledger, self.runtime, rule.inputs, rule.probes,
            rule.compiler or None, through_seq)
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
        evaluation = _evaluation_snapshot(
            rule,
            ctx.trace,
            severity=severity,
            message=message,
            ledger=ledger,
            trigger_event=trigger_event,
            context_through_seq=through_seq,
            rule_result=result,
        )
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


def _input_segments(text: str) -> list[dict[str, Any]]:
    headings = (
        ("## Probes", "probes"),
        ("## Latest", "latest"),
        ("## Recent activity", "recent_activity"),
    )
    found = []
    for marker, kind in headings:
        start = text.find(marker)
        if start >= 0:
            found.append((start, kind))
    found.sort()
    segments = []
    for index, (start, kind) in enumerate(found):
        end = found[index + 1][0] if index + 1 < len(found) else len(text)
        segments.append({
            "kind": kind,
            "start": start,
            "end": end,
        })
    return segments


def _evaluation_snapshot(
    rule: LoadedRule,
    trace: list[dict[str, Any]],
    *,
    severity: str,
    message: str,
    ledger: Ledger,
    trigger_event: Event | None,
    context_through_seq: int,
    rule_result: Any,
) -> dict[str, Any]:
    paw_entries = [
        item for item in trace if item.get("type") == "paw"]
    evidence_entries = [
        item for item in trace if item.get("type") == "evidence"]
    result_trace_index = getattr(rule_result, "trace_index", None)
    finding_trace = (
        trace[result_trace_index]
        if isinstance(result_trace_index, int)
        and 0 <= result_trace_index < len(trace)
        and trace[result_trace_index].get("type") == "finding_result"
        else {}
    )
    selected_index = finding_trace.get("paw_trace_index")
    paw = (
        trace[selected_index]
        if isinstance(selected_index, int)
        and 0 <= selected_index < len(trace)
        and trace[selected_index].get("type") == "paw"
        else {}
    )
    evidence = evidence_entries[-1] if evidence_entries else {}
    input_text = str(
        paw.get("input")
        if paw else
        paw_entries[-1].get("input", "")
        if paw_entries else evidence.get("text", ""))
    raw_output = (
        str(paw.get("output", "")) if paw
        else _raw_rule_result(rule_result)
    )
    raw_output_bytes = raw_output.encode("utf-8")
    standard_input = bool(
        paw and evidence and input_text == str(evidence.get("text", "")))
    included_ids = (
        {
            str(item.get("id", ""))
            for item in [
                *list(evidence.get("latest") or []),
                *list(evidence.get("events") or []),
            ]
            if item.get("id") and item.get("input_span")
        }
        if standard_input else set()
    )
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
        "schema_version": 2,
        "kind": (
            "paw" if paw
            else "composite" if paw_entries
            else "untraced_fuzzy" if rule.spec
            else "deterministic"
        ),
        "calls": [
            {
                "input": str(item.get("input", "")),
                "output": str(item.get("output", "")),
            }
            for item in paw_entries
        ],
        "rule": {
            "id": rule.id,
            "name": rule.title,
            "compiler": rule.compiler,
            "program_id": rule.program_id,
        },
        "input": {
            "text": input_text,
            "sha256": hashlib.sha256(input_bytes).hexdigest(),
            "char_count": len(input_text),
            "byte_count": len(input_bytes),
            "recording_complete": bool(paw_entries or evidence),
            "truncation_reason": (
                "no_universal_deterministic_input"
                if not paw_entries and not evidence and not rule.spec else
                "untraced_fuzzy_input"
                if not paw_entries and not evidence and rule.spec else
                "unattributed_paw_call"
                if paw_entries and not paw else
                "rule_input_limit"
                if input_text.startswith("...\n") else ""
            ),
            "role": (
                "evaluated_input" if paw
                else "unattributed_paw_call" if paw_entries
                else "recorded_evidence" if evidence
                else "unavailable"
            ),
            "format": (
                "rap-evidence-v1" if standard_input else "plain"),
            "segments": (
                _input_segments(input_text) if standard_input else []),
            "event_ids": sorted(included_ids),
            "event_segments": [
                {
                    "event_id": str(item.get("id", "")),
                    "start": int(item["input_span"][0]),
                    "end": int(item["input_span"][1]),
                    "inclusion": item.get("input_inclusion", "full"),
                }
                for item in [
                    *list(evidence.get("latest") or []),
                    *list(evidence.get("events") or []),
                ]
                if standard_input and item.get("id") and item.get("input_span")
            ],
            "source_mapping_available": standard_input,
        },
        "output": {
            "raw": raw_output,
            "sha256": hashlib.sha256(raw_output_bytes).hexdigest(),
            "char_count": len(raw_output),
            "byte_count": len(raw_output_bytes),
            "recording_complete": True,
            "severity": severity,
            "message": message,
        },
        "trigger": {
            "event_id": trigger_event.id if trigger_event else "",
            "kind": trigger_event.kind if trigger_event else "",
            "seq": trigger_index + 1 if trigger_index >= 0 else None,
            "included_in_input": (
                bool(trigger_event and trigger_event.id in included_ids)
                if standard_input else None),
            "event": (
                {
                    **trigger_event.to_dict(),
                    "text": trigger_event.text(),
                }
                if trigger_event else None
            ),
        },
        "context_through_seq": through_seq,
        "trace_call_count": len(trace),
    }


def _raw_rule_result(result: Any) -> str:
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return repr(result)
