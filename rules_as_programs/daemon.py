"""The long-lived Rules-as-Programs daemon.

* Owns a warm shared :class:`PawRuntime` so rule judges never pay cold-start on
  the agent's critical path.
* Keeps a per-conversation evidence :class:`Ledger`.
* Runs the rule :class:`Engine` off the request thread (events return instantly,
  judgment happens in the background) -> the agent is never blocked.
* Persists verdicts to the :class:`VerdictStore` (for the tray / ``rap status``)
  and writes per-project audit logs.

Protocol (newline-delimited JSON over a Unix socket), one request/response:
``ping``/``snapshot``, ``event``, ``warm``, finding detail/review/history,
project/rule state and source operations, ``compile``, ``test``, ``shutdown``.
"""

from __future__ import annotations

import json
import hashlib
import os
import secrets
import socketserver
import sys
import threading
import time
import traceback
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None

from . import __version__, config, paw_runtime, rules_api, scaffold
from .adapters.codex import projects as codex_projects
from .adapters.codex.adapter import event_identity
from .core import audit, evaluation_log
from .core.attention import AttentionStore
from .core.engine import Engine, RuleContext
from .core.events import (
    Event,
    QUESTION_REQUEST,
    SESSION_START,
    SESSION_STOP,
    USER_PROMPT,
)
from .core.ledger import LedgerStore
from .core.incidents import IncidentStore
from .core import deployment_queue, revisions, validation_store
from .core.rule import (
    LoadedRule,
    RuleLoadError,
    load_rule_file,
    load_rules_with_errors,
    new_rule_id,
    rule_paths,
)
from .core.store import VerdictStore, reset_development_finding_history
from .core.triggers import extract_input
from .ipc import PROTOCOL_VERSION
from .sdk import RULE_ATTR, RuleDef


def _log(msg: str) -> None:
    try:
        with config.log_path().open("a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except OSError:
        pass


class _RulesCache:
    """Caches loaded rules per project, invalidating on rule-file mtime changes."""

    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, list[LoadedRule], list[RuleLoadError]]] = {}
        self._lock = threading.Lock()

    def _signature(self, project_root: str) -> float:
        latest = 0.0
        dirs = [config.global_rules_dir()]
        if project_root:
            dirs.append(config.project_rules_dir(project_root))
        for d in dirs:
            for p in rule_paths(d):
                try:
                    latest = max(latest, p.stat().st_mtime)
                except OSError:
                    pass
        return latest

    def get(self, project_root: str) -> list[LoadedRule]:
        sig = self._signature(project_root)
        with self._lock:
            cached = self._cache.get(project_root)
            if cached and cached[0] == sig:
                return cached[1]
        rules, errors = load_rules_with_errors(project_root or None)
        active_rules: list[LoadedRule] = []
        for rule in rules:
            info = revisions.active_info(rule.id, rule.source_path)
            if info:
                loaded = load_rule_file(Path(info["cache_path"]), rule.scope)
                if loaded:
                    active_rule = loaded[0]
                    # Name is descriptive metadata and follows the current
                    # working source without activating new behavior.
                    active_rule.title = rule.title
                    active_rule.source_path = info["cache_path"]
                    active_rule.working_source_path = rule.source_path
                    active_rule.compiler = str(info.get("compiler", ""))
                    active_rule.compiler_snapshot = str(
                        info.get("compiler_snapshot", "")
                    )
                    active_rule.program_id = str(info.get("program_id", ""))
                    active_rules.append(active_rule)
                    continue
            active_rules.append(rule)
        rules = active_rules
        with self._lock:
            self._cache[project_root] = (sig, rules, errors)
        return rules

    def errors(self, project_root: str) -> list[RuleLoadError]:
        self.get(project_root)
        with self._lock:
            cached = self._cache.get(project_root)
            return list(cached[2]) if cached else []

    def invalidate(self) -> None:
        with self._lock:
            self._cache.clear()


class Daemon:
    INGRESS_DEDUP_TTL_SECONDS = 60.0
    INGRESS_DEDUP_MAX_ENTRIES = 4096

    def __init__(self) -> None:
        self.started_at = time.time()
        self.runtime = paw_runtime.shared()
        scaffold.prune_obsolete_managed_rules(
            [
                str(item.get("path", ""))
                for item in codex_projects.discover_projects(limit=100)
                if item.get("path")
            ]
        )
        reset_development_finding_history()
        self.store = VerdictStore()
        self.attention = AttentionStore()
        self.incidents = IncidentStore()
        self.validation_results = validation_store.ValidationResultStore()
        self.deployment_queue = deployment_queue.DeploymentQueueStore()
        self.ledgers = LedgerStore()
        self.rules_cache = _RulesCache()
        self.engine = Engine(
            self.runtime,
            self.store,
            self.rules_cache.get,
            on_verdict=self._on_verdict,
            on_error=self._on_rule_error,
            on_success=self._on_rule_success,
            is_muted=rules_api.is_muted,
            is_enabled=rules_api.is_enabled,
        )
        self.work = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rap-work")
        self.optimization_work = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="rap-optimize"
        )
        self._warmed: set[str] = set()
        self.known_projects: set[str] = set()
        self._state_lock = threading.Lock()
        self._warm_state: dict[str, dict[str, dict[str, Any]]] = {}
        self._warm_generation: dict[str, int] = {}
        self._project_activity: dict[str, dict[str, Any]] = {}
        self._ingress_seen: OrderedDict[str, float] = OrderedDict()
        self._ingress_dedup_lock = threading.Lock()
        self._ingress_duplicate_count = 0
        self._prepared_deployments: dict[str, dict[str, Any]] = {}
        self._deployment_lock = threading.Lock()
        self._finetune_jobs: dict[str, dict[str, Any]] = {}
        self._finetune_lock = threading.Lock()
        self._workflow_admission_lock = threading.Lock()
        self._queued_deployment_lock = threading.Lock()
        self._queued_deployments_running: set[str] = set()
        self._queued_validation_lock = threading.Lock()
        self._queued_validations_running: set[str] = set()
        self._last_successful_audit = 0.0
        self._stop = threading.Event()
        for queued in self.deployment_queue.pending():
            kind = str(queued.get("kind") or deployment_queue.DEPLOYMENT_KIND)
            if kind == deployment_queue.OPTIMIZATION_KIND:
                runner = self._run_optimization
                executor = self.optimization_work
            elif kind == deployment_queue.VALIDATION_KIND:
                runner = self._run_queued_validation
                executor = self.work
            else:
                runner = self._run_queued_deployment
                executor = self.work
            executor.submit(runner, str(queued.get("id", "")))

    # --- event handling --------------------------------------------------
    def _admit_ingress_event(self, event: Event, *, now: float | None = None) -> bool:
        identity = event_identity(event)
        if not identity:
            return True
        current = time.monotonic() if now is None else float(now)
        cutoff = current - self.INGRESS_DEDUP_TTL_SECONDS
        with self._ingress_dedup_lock:
            while self._ingress_seen:
                _oldest_key, oldest_at = next(iter(self._ingress_seen.items()))
                if oldest_at > cutoff:
                    break
                self._ingress_seen.popitem(last=False)
            if identity in self._ingress_seen:
                self._ingress_seen.move_to_end(identity)
                self._ingress_seen[identity] = current
                self._ingress_duplicate_count += 1
                return False
            self._ingress_seen[identity] = current
            while len(self._ingress_seen) > self.INGRESS_DEDUP_MAX_ENTRIES:
                self._ingress_seen.popitem(last=False)
        return True

    def handle_event(self, ev_dict: dict[str, Any]) -> bool:
        event = Event.from_dict(ev_dict)
        if not self._admit_ingress_event(event):
            return False
        if event.project_root:
            with self._state_lock:
                self.known_projects.add(event.project_root)
                activity = self._project_activity.setdefault(event.project_root, {})
                previous_generation = activity.get("generation_id", "")
                activity.update(
                    {
                        "last_event_ts": event.ts,
                        "last_event_kind": event.kind,
                        "conversation_id": event.conversation_id,
                        "generation_id": event.generation_id,
                    }
                )
                if event.kind != SESSION_STOP:
                    activity["active"] = True
                    if event.generation_id != previous_generation:
                        activity["turn_started_at"] = event.ts
                else:
                    activity["active"] = False
                    activity["session_stopped_at"] = event.ts
        ledger = self.ledgers.get(event.conversation_id, event.project_root)
        ledger.append(event)  # fast, synchronous
        if event.kind == USER_PROMPT:
            self.attention.clear(
                conversation_id=event.conversation_id, reason="user replied"
            )
        if rules_api.monitoring_paused():
            return True
        if event.project_root and not rules_api.project_enabled(event.project_root):
            return True  # monitoring is off for this project
        if event.kind == QUESTION_REQUEST:
            self.attention.set(
                project_root=event.project_root,
                conversation_id=event.conversation_id,
                generation_id=event.generation_id,
                message=event.text(),
                confidence="explicit",
                source="ask_question_tool",
            )
        self.work.submit(self._evaluate, event, ledger)
        if event.hook_name == "Stop":
            self.work.submit(self._evaluate_attention, event, ledger)
        should_warm = False
        if event.kind == SESSION_START:
            with self._state_lock:
                if event.project_root not in self._warmed:
                    self._warmed.add(event.project_root)
                    should_warm = True
        if should_warm:
            self.work.submit(self._warm, event.project_root)
        return True

    def _evaluate(self, event: Event, ledger) -> None:
        try:
            self.engine.on_event(event, ledger)
        except Exception as exc:
            _log(f"evaluate error: {exc!r}")

    def _evaluate_attention(self, event: Event, ledger) -> None:
        rule_id = "gn3xtat6av4fy690"
        if not self._rule_enabled(rule_id, event.project_root):
            return
        evaluation_id = secrets.token_hex(16)
        started_at = time.time()
        started_logged = False
        rule = None
        try:
            rule = next(
                (
                    item
                    for item in self.rules_cache.get(event.project_root)
                    if item.id == rule_id
                ),
                None,
            )
            if rule is None or rule.channel != "attention":
                return
            if rule.trigger != event.hook_name:
                return
            input_text, _pointer, _value_type, _overridden = extract_input(
                rule.trigger, event.raw_payload, rule.input_pointer
            )
            source = ""
            if rule.source_path:
                try:
                    source = Path(rule.source_path).read_text(encoding="utf-8")
                except OSError:
                    source = ""
            evaluation_log.started(
                event.project_root,
                {
                    "evaluation_id": evaluation_id,
                    "timestamp": started_at,
                    "project_root": event.project_root,
                    "conversation_id": event.conversation_id,
                    "rule": {
                        "id": rule.id,
                        "name": rule.title,
                        "source_hash": revisions.hash_source(source) if source else "",
                        "behavior_hash": (
                            revisions.behavior_hash(source) if source else ""
                        ),
                        "compiler": rule.compiler or "",
                        "compiler_snapshot": rule.compiler_snapshot or "",
                        "program_id": rule.program_id or "",
                    },
                    "trigger": {
                        "hook": event.hook_name,
                        "event_id": event.id,
                        "kind": event.kind,
                    },
                    "input": {
                        "json_pointer": _pointer,
                        "pointer_source": ("override" if _overridden else "default"),
                        "value_type": _value_type,
                        "text": input_text,
                        "sha256": hashlib.sha256(
                            input_text.encode("utf-8")
                        ).hexdigest(),
                        "byte_count": len(input_text.encode("utf-8")),
                    },
                },
            )
            started_logged = True
            input_bytes = len(input_text.encode("utf-8"))
            if input_bytes > rule.max_input_bytes:
                message = (
                    f"input too large: {input_bytes} bytes exceeds "
                    f"{rule.max_input_bytes}"
                )
                evaluation_log.failed(
                    event.project_root,
                    {
                        "evaluation_id": evaluation_id,
                        "timestamp": time.time(),
                        "duration_ms": int((time.time() - started_at) * 1000),
                        "error_code": "input_too_large",
                        "error": message,
                    },
                )
                self._on_rule_error(rule, event.project_root, message)
                return
            context = RuleContext(
                ledger,
                self.runtime,
                rule.compiler or None,
                input_text=input_text,
                default_program_id=rule.program_id or None,
                default_spec=rule.spec,
            )
            result = rule.fn(context)
            if not result:
                evaluation_log.completed(
                    event.project_root,
                    {
                        "evaluation_id": evaluation_id,
                        "timestamp": time.time(),
                        "duration_ms": int((time.time() - started_at) * 1000),
                        "result": "OK",
                        "finding_id": None,
                        "attention_id": None,
                    },
                )
                return
            latest = input_text
            attention_id = self.attention.set(
                project_root=event.project_root,
                conversation_id=event.conversation_id,
                generation_id=event.generation_id,
                message=latest or str(result),
                confidence="inferred",
                source=rule_id,
            )
            evaluation_log.completed(
                event.project_root,
                {
                    "evaluation_id": evaluation_id,
                    "timestamp": time.time(),
                    "duration_ms": int((time.time() - started_at) * 1000),
                    "result": str(result[0]).upper(),
                    "finding_id": None,
                    "attention_id": attention_id,
                },
            )
        except Exception as exc:
            if rule is not None:
                if not started_logged:
                    evaluation_log.started(
                        event.project_root,
                        {
                            "evaluation_id": evaluation_id,
                            "timestamp": started_at,
                            "project_root": event.project_root,
                            "conversation_id": event.conversation_id,
                            "rule": {"id": rule.id, "name": rule.title},
                            "trigger": {
                                "hook": event.hook_name,
                                "event_id": event.id,
                                "kind": event.kind,
                            },
                            "input": {
                                "json_pointer": rule.input_pointer,
                                "text": None,
                            },
                        },
                    )
                evaluation_log.failed(
                    event.project_root,
                    {
                        "evaluation_id": evaluation_id,
                        "timestamp": time.time(),
                        "duration_ms": int((time.time() - started_at) * 1000),
                        "error_code": "runtime_exception",
                        "error": str(exc),
                    },
                )
            _log(f"attention evaluate error: {exc!r}")

    def _warm(self, project_root: str) -> None:
        with self._state_lock:
            if not hasattr(self, "_warm_generation"):
                self._warm_generation = {}
            generation = self._warm_generation.get(project_root, 0) + 1
            self._warm_generation[project_root] = generation
        rules = list(self.rules_cache.get(project_root))
        with self._state_lock:
            project_state = self._warm_state.setdefault(project_root, {})
            for rule in rules:
                project_state[rule.id] = {
                    "status": "disabled"
                    if not self._rule_enabled(rule.id, project_root)
                    else "warming",
                    "updated_at": time.time(),
                    "error": "",
                }
        try:
            results: dict[str, bool] = {}
            for rule in rules:
                if not self._rule_enabled(rule.id, project_root):
                    results[rule.id] = False
                    continue
                if not rule.spec:
                    self._set_warm_state(
                        project_root, rule.id, "ready", generation=generation
                    )
                    results[rule.id] = True
                    continue
                if not self.runtime.available:
                    self._set_warm_state(
                        project_root,
                        rule.id,
                        "failed",
                        "PAW SDK is unavailable",
                        generation=generation,
                    )
                    results[rule.id] = False
                    continue
                pid = rule.program_id or self.runtime.program_id_for_spec(
                    rule.spec, rule.compiler or None
                )
                if not pid:
                    self._set_warm_state(
                        project_root,
                        rule.id,
                        "failed",
                        "Rule compilation failed",
                        generation=generation,
                    )
                    results[rule.id] = False
                    continue
                ok = self.runtime.warm(pid)
                self._set_warm_state(
                    project_root,
                    rule.id,
                    "ready" if ok else "failed",
                    "" if ok else "Local PAW model failed to warm",
                    generation=generation,
                )
                results[rule.id] = ok
            with self._state_lock:
                if self._warm_generation.get(project_root) != generation:
                    return
            for rule in rules:
                if not self._rule_enabled(rule.id, project_root):
                    continue
                if results.get(rule.id):
                    self.incidents.clear(
                        project_root=project_root, rule_id=rule.id, code="warm_failure"
                    )
                    continue
                state = self._warm_state.get(project_root, {}).get(rule.id, {})
                if state.get("status") == "failed":
                    self.incidents.record(
                        "warm_failure",
                        project_root=project_root,
                        rule_id=rule.id,
                        rule_name=rule.title,
                        summary=f"{rule.title} could not prepare its local model",
                        detail=str(state.get("error", "")),
                        impact="this fuzzy rule is not running",
                        threshold=1,
                    )
            _log(f"warmed {project_root}: {results}")
        except Exception as exc:
            _log(f"warm error: {exc!r}")
            with self._state_lock:
                if self._warm_generation.get(project_root) != generation:
                    return
                state = self._warm_state.setdefault(project_root, {})
                for rule in rules:
                    if state.get(rule.id, {}).get("status") == "warming":
                        state[rule.id] = {
                            "status": "failed",
                            "updated_at": time.time(),
                            "error": str(exc),
                        }
                        self.incidents.record(
                            "warm_failure",
                            project_root=project_root,
                            rule_id=rule.id,
                            rule_name=rule.title,
                            summary=(f"{rule.title} could not prepare its local model"),
                            detail=str(exc),
                            impact="this fuzzy rule is not running",
                            threshold=1,
                        )

    @staticmethod
    def _rule_enabled(rule_id: str, project_root: str) -> bool:
        """Compatibility shim while state migrated from global to scoped keys."""
        try:
            return bool(rules_api.is_enabled(rule_id, project_root))
        except TypeError:  # pragma: no cover - old state API during upgrades
            return bool(rules_api.is_enabled(rule_id))

    def _set_warm_state(
        self,
        project_root: str,
        rule_id: str,
        status: str,
        error: str = "",
        *,
        generation: int | None = None,
    ) -> None:
        with self._state_lock:
            if (
                generation is not None
                and self._warm_generation.get(project_root) != generation
            ):
                return
            self._warm_state.setdefault(project_root, {})[rule_id] = {
                "status": status,
                "updated_at": time.time(),
                "error": error,
            }

    def _on_verdict(self, verdict) -> None:
        with self._state_lock:
            self._last_successful_audit = verdict.ts
        _log(f"verdict [{verdict.severity}] {verdict.rule_id}")

    def _on_rule_error(self, rule: LoadedRule, project_root: str, message: str) -> None:
        code = (
            "input_too_large"
            if "input too large" in message
            else "input_field_missing"
            if "input field missing" in message
            else "invalid_output"
            if "invalid fuzzy severity" in message
            else "runtime_exception"
        )
        summary = (
            f"{rule.title} input is too large"
            if code == "input_too_large"
            else f"{rule.title} input field is unavailable"
            if code == "input_field_missing"
            else f"{rule.title} check returned no valid decision"
            if code == "invalid_output"
            else f"{rule.title} check failed"
        )
        self.incidents.record(
            code,
            project_root=project_root,
            rule_id=rule.id,
            rule_name=rule.title,
            summary=summary,
            detail=message,
            impact="this rule check was skipped",
            threshold=1 if code.startswith("input_") else 2,
        )
        _log(f"rule error {rule.id} project={project_root}: {message}")

    def _on_rule_success(self, rule: LoadedRule, project_root: str) -> None:
        for code in (
            "invalid_output",
            "runtime_exception",
            "input_too_large",
            "input_field_missing",
        ):
            self.incidents.clear(code=code, project_root=project_root, rule_id=rule.id)
        with self._state_lock:
            self._last_successful_audit = time.time()

    # --- status snapshot -------------------------------------------------
    @staticmethod
    def _hooks_installed(project_root: str) -> bool:
        """Check for our hook in either project or global Codex config."""
        for path in (
            config.codex_hooks_path("project", project_root),
            config.codex_hooks_path("global"),
        ):
            if not path.exists():
                continue
            try:
                if "rap-hook" in path.read_text(encoding="utf-8"):
                    return True
            except OSError:
                continue
        return False

    def _project_summaries(
        self,
        active_findings: dict[str, list[dict[str, Any]]],
        attention: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        discovered = codex_projects.discover_projects(limit=100)
        discovered_by_path = {item["path"]: item for item in discovered}
        paths = list(discovered_by_path)

        with self._state_lock:
            known_projects = list(self.known_projects)
            activity = {k: dict(v) for k, v in self._project_activity.items()}
            warm = {
                project: {rid: dict(value) for rid, value in states.items()}
                for project, states in self._warm_state.items()
            }
        attention_paths = [item.get("project_root", "") for item in attention]
        for path in known_projects + list(active_findings) + attention_paths:
            if path and path not in paths and path != "(unknown)":
                paths.append(path)

        out: list[dict[str, Any]] = []
        for path in paths:
            rules = self.rules_cache.get(path)
            load_errors = self.rules_cache.errors(path)
            enabled = [r for r in rules if self._rule_enabled(r.id, path)]
            warm_states = warm.get(path, {})
            statuses = [v.get("status") for v in warm_states.values()]
            monitoring = rules_api.project_enabled(path)
            globally_paused = rules_api.monitoring_paused()
            hooks = self._hooks_installed(path)
            has_paw = any(r.spec for r in enabled)
            if globally_paused or not monitoring:
                status = "paused"
            elif load_errors and not rules:
                status = "failed"
            elif not hooks or not rules:
                status = "setup_needed"
            elif not enabled:
                status = "disabled"
            elif has_paw and not self.runtime.available:
                status = "failed"
            elif load_errors:
                status = "degraded"
            elif "failed" in statuses:
                status = "degraded"
            elif "warming" in statuses:
                status = "warming"
            elif warm_states:
                status = "ready"
            else:
                status = "idle"
            recent = discovered_by_path.get(path, {})
            details = activity.get(path, {})
            out.append(
                {
                    "path": path,
                    "name": Path(path).name or path,
                    "workspace_mtime": recent.get("mtime", 0),
                    "monitoring": monitoring,
                    "globally_paused": globally_paused,
                    "hooks_installed": hooks,
                    "status": status,
                    "active": bool(details.get("active")),
                    "last_event_ts": details.get("last_event_ts", 0),
                    "last_event_kind": details.get("last_event_kind", ""),
                    "conversation_id": details.get("conversation_id", ""),
                    "rule_count": len(rules),
                    "enabled_rule_count": len(enabled),
                    "rule_errors": [
                        {"path": error.path, "scope": error.scope, "error": error.error}
                        for error in load_errors
                    ],
                    "open_count": len(active_findings.get(path, [])),
                    "attention_count": sum(
                        1 for item in attention if item.get("project_root") == path
                    ),
                    "warm": warm_states,
                }
            )
        out.sort(
            key=lambda item: (
                bool(item["active"]),
                item["last_event_ts"] or item["workspace_mtime"],
            ),
            reverse=True,
        )
        return out

    def _archive_orphaned_findings(self, rule_id: str | None = None) -> int:
        """Move findings without an installed rule definition into history."""
        archived = 0
        for grouped_root, groups in self.store.by_project().items():
            project_root = str(
                (groups[0].get("project_root") if groups else "")
                or ("" if grouped_root == "(unknown)" else grouped_root)
            )
            candidate_ids = {
                str(group.get("rule_id", ""))
                for group in groups
                if group.get("rule_id")
                and (rule_id is None or group.get("rule_id") == rule_id)
            }
            for candidate_id in candidate_ids:
                try:
                    current = rules_api.get_rule(candidate_id, project_root)
                except Exception:
                    # A transient read/import failure is not a deletion.
                    continue
                installed = bool(
                    current
                    and current.get("scope") in ("global", "project")
                    and current.get("definition")
                )
                if not installed:
                    archived += self.store.acknowledge_rule(
                        candidate_id, project_root, reason="rule_deleted"
                    )
        return archived

    @staticmethod
    def _decorate_finding_group(group: dict[str, Any], summary: dict[str, Any]) -> bool:
        current_hash = summary.get("active_hash") or summary.get("working_hash") or ""
        current_behavior_hash = str(
            summary.get("active_behavior_hash")
            or summary.get("working_behavior_hash")
            or summary.get("behavior_hash")
            or ""
        )
        evaluation_rule = (group.get("evaluation") or {}).get("rule") or {}
        recorded_behavior_hash = str(
            group.get("behavior_hash") or evaluation_rule.get("behavior_hash") or ""
        )
        if not recorded_behavior_hash:
            recorded_source = str(evaluation_rule.get("source", ""))
            if recorded_source:
                recorded_behavior_hash = revisions.behavior_hash(recorded_source)
        stale = bool(
            recorded_behavior_hash
            and current_behavior_hash
            and recorded_behavior_hash != current_behavior_hash
        )
        group["stale"] = stale
        group["current_source_hash"] = current_hash
        group["current_behavior_hash"] = current_behavior_hash
        group["recorded_rule_title"] = group.get("rule_title", "")
        current_name = str(summary.get("name") or summary.get("title") or "")
        if current_name:
            group["rule_title"] = current_name
        return stale

    def snapshot(self) -> dict[str, Any]:
        self._archive_orphaned_findings()
        all_findings = self.store.by_project()
        active_findings: dict[str, list[dict[str, Any]]] = {}
        stale_findings: dict[str, list[dict[str, Any]]] = {}
        for project_root, groups in all_findings.items():
            summaries = {
                rule["id"]: rule for rule in rules_api.list_rules(project_root)
            }
            for group in groups:
                summary = summaries.get(group.get("rule_id"), {})
                stale = self._decorate_finding_group(group, summary)
                target = stale_findings if stale else active_findings
                target.setdefault(project_root, []).append(group)
        combined = {
            project: [
                *active_findings.get(project, []),
                *stale_findings.get(project, []),
            ]
            for project in set(active_findings) | set(stale_findings)
        }
        attention = self.attention.active()
        projects = self._project_summaries(active_findings, attention)
        health_issues = self.incidents.active()
        import_groups: dict[tuple[str, str], dict[str, Any]] = {}
        for project in projects:
            for error in project.get("rule_errors", []):
                rule_name = Path(error.get("path", "")).parent.name
                key = (rule_name, str(error.get("error", "")))
                issue = import_groups.setdefault(
                    key,
                    {
                        "code": "import_error",
                        "project_root": project["path"],
                        "rule_id": "",
                        "rule_name": rule_name,
                        "summary": f"{rule_name or 'A rule'} could not load",
                        "detail": error.get("error", ""),
                        "impact": "that rule is not running",
                        "count": 1,
                        "threshold": 1,
                        "affected_projects": [],
                    },
                )
                if project["path"] not in issue["affected_projects"]:
                    issue["affected_projects"].append(project["path"])
            if (
                not project.get("hooks_installed")
                and project.get("rule_count")
                and project.get("monitoring")
            ):
                health_issues.append(
                    {
                        "code": "hooks_missing",
                        "project_root": project["path"],
                        "rule_id": "",
                        "rule_name": "",
                        "summary": f"Auditing is not connected to {project['name']}",
                        "detail": "Codex hooks are missing, invalid, or not trusted.",
                        "impact": "agent activity is not being audited",
                        "count": 1,
                        "threshold": 1,
                        "affected_projects": [project["path"]],
                    }
                )
        for issue in import_groups.values():
            affected = len(issue["affected_projects"])
            if affected > 1:
                issue["summary"] = (
                    f"{issue['rule_name'] or 'A rule'} could not load in "
                    f"{affected} projects"
                )
            health_issues.append(issue)
        statuses = {item["status"] for item in projects}
        paused = rules_api.monitoring_paused()
        if paused:
            health = "paused"
        elif health_issues or "failed" in statuses or "degraded" in statuses:
            health = "degraded"
        elif "warming" in statuses:
            health = "warming"
        elif "idle" in statuses or "disabled" in statuses:
            health = "idle"
        elif projects and all(item["status"] == "paused" for item in projects):
            health = "paused"
        else:
            health = "ready"
        with self._state_lock:
            last_audit = self._last_successful_audit
        with self._ingress_dedup_lock:
            ingress_duplicates = self._ingress_duplicate_count
        return {
            "ok": True,
            "protocol": PROTOCOL_VERSION,
            "version": __version__,
            "daemon": {
                "pid": os.getpid(),
                "started_at": self.started_at,
                "paw_available": self.runtime.available,
                "health": health,
                "monitoring_paused": paused,
                "last_successful_audit": last_audit,
                "ingress_duplicates": ingress_duplicates,
            },
            "projects": projects,
            "health_issues": health_issues,
            "findings_by_project": combined,
            "stale_findings_by_project": stale_findings,
            "attention": attention,
            "attention_count": len(attention),
            "open_count": sum(len(rows) for rows in active_findings.values()),
            "stale_count": sum(len(rows) for rows in stale_findings.values()),
            "project_count": sum(1 for p in projects if p["monitoring"]),
        }

    # --- PAW-backed rule operations (use the warm runtime) ---------------
    def _rule_from(
        self, rule_id: str, project_root: str, source: str | None
    ) -> LoadedRule | None:
        if source:
            ns: dict[str, Any] = {"__name__": "rap_rule_edit"}
            try:
                exec(compile(source, "<rule>", "exec"), ns)
            except Exception:
                return None
            match = None
            for value in ns.values():
                rd = getattr(value, RULE_ATTR, None)
                if isinstance(rd, RuleDef):
                    match = match or LoadedRule.from_def(rd, "edit", "")
                    if rd.id == rule_id:
                        return LoadedRule.from_def(rd, "edit", "")
            return match
        for rule in self.rules_cache.get(project_root):
            if rule.id == rule_id:
                return rule
        info = rules_api.get_rule(rule_id, project_root)
        if info and info.get("source"):
            return self._rule_from(rule_id, project_root, info["source"])
        return None

    def compile_rule(
        self,
        rule_id: str,
        project_root: str,
        finalize: bool = False,
        source: str | None = None,
        compiler: str | None = None,
        expected_snapshot: str = "",
    ) -> dict[str, Any]:
        if not self.runtime.available:
            return {"ok": False, "error": "PAW SDK not available"}
        rule = self._rule_from(rule_id, project_root, source)
        if rule is None or not rule.spec:
            return {"ok": False, "error": "rule has no PAW spec"}
        compiler_info = self.runtime.compiler_info(compiler or "")
        if finalize and not compiler:
            compiler_info = self.runtime.compatible_finetune_compiler("")
            compiler = str(compiler_info.get("name", "")) or None
            if not compiler:
                return {
                    "ok": False,
                    "error": "No compatible finetune compiler is available.",
                }
        compiler_kind = str(compiler_info.get("compiler_kind", ""))
        self._set_warm_state(project_root, rule.id, "warming")
        compiled = self._compile_program_for_snapshot(
            rule.spec,
            compiler or "",
            expected_snapshot,
            timeout=360 if compiler_kind == "finetune_lora" else None,
        )
        pid = str(compiled.get("program_id", ""))
        if not pid:
            self._set_warm_state(
                project_root,
                rule.id,
                "failed",
                str(compiled.get("error", "Compilation failed or timed out")),
            )
            return compiled
        compiler_info = dict(compiled.get("compiler_info") or compiler_info)
        warmed = self.runtime.warm(pid)
        self._set_warm_state(
            project_root,
            rule.id,
            "ready" if warmed else "failed",
            "" if warmed else "Local PAW model failed to warm",
        )
        if not warmed:
            return {"ok": False, "error": "compiled, but local model failed to warm"}
        return {
            "ok": True,
            "program_id": pid,
            "finalized": compiler_kind == "finetune_lora",
            "compiler": compiler or str(compiler_info.get("name", "")),
            "compiler_info": compiler_info,
            "compiler_snapshot": str(compiled.get("compiler_snapshot", "")),
        }

    def _automatic_base_compiler(self) -> dict[str, Any]:
        resolver = getattr(self.runtime, "automatic_base_compiler", None)
        if callable(resolver):
            return dict(resolver() or {})
        return dict(self.runtime.compiler_info("") or {})

    def _compile_program_for_snapshot(
        self,
        spec: str,
        compiler: str,
        expected_snapshot: str,
        *,
        timeout: float | None,
    ) -> dict[str, Any]:
        """Compile only while the selected compiler revision remains exact."""

        def current_info() -> dict[str, Any]:
            list_compilers = getattr(self.runtime, "list_compilers", None)
            if callable(list_compilers):
                try:
                    list_compilers(refresh=True, max_age=0)
                except TypeError:
                    try:
                        list_compilers(refresh=True)
                    except TypeError:
                        pass
                    except Exception:
                        pass
                except Exception:
                    pass
            return dict(self.runtime.compiler_info(compiler) or {})

        before = current_info()
        before_snapshot = str(before.get("latest_snapshot", ""))
        if expected_snapshot and before_snapshot != expected_snapshot:
            return {
                "ok": False,
                "compiler_catalog_stale": True,
                "error": "The selected compiler revision is no longer available.",
            }
        pinned_snapshot = expected_snapshot or before_snapshot
        program_id = str(
            self.runtime.program_id_for_spec(
                spec,
                compiler or None,
                timeout=timeout,
            )
            or ""
        )
        if not program_id:
            return {
                "ok": False,
                "error": "The compiler build failed or timed out.",
            }
        after = current_info()
        after_snapshot = str(after.get("latest_snapshot", ""))
        if pinned_snapshot and after_snapshot != pinned_snapshot:
            return {
                "ok": False,
                "compiler_catalog_stale": True,
                "error": (
                    "The compiler changed while this build was running. "
                    "Queue the action again against the new revision."
                ),
            }
        return {
            "ok": True,
            "program_id": program_id,
            "compiler_snapshot": after_snapshot or pinned_snapshot,
            "compiler_info": after or before,
        }

    def start_finetune(
        self,
        rule_id: str,
        project_root: str,
        compiler_name: str = "",
        source: str = "",
        validation_cases: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        info = rules_api.get_rule(rule_id, project_root or None) or {}
        active = info.get("active") or {}
        source_path = str((info.get("definition") or {}).get("source_path", ""))
        if source:
            source_hash = revisions.hash_source(source)
            source_behavior_hash = revisions.behavior_hash(source)
            cases = rules_api.normalize_validation_cases(validation_cases)
        else:
            source_hash = str(active.get("source_hash", ""))
            source_behavior_hash = str(active.get("behavior_hash", ""))
            cache_path = Path(str(active.get("cache_path", "")))
            if not source_hash or not cache_path.exists():
                return {"ok": False, "error": "Rule source is unavailable."}
            try:
                source = cache_path.read_text(encoding="utf-8")
            except OSError:
                return {
                    "ok": False,
                    "error": "Deployed rule source is unavailable.",
                }
            if not source_behavior_hash:
                source_behavior_hash = revisions.behavior_hash(source)
            cases = rules_api.validation_cases_for_path(source_path)
        compiler_info = (
            self.runtime.compiler_info(compiler_name)
            if compiler_name
            else self.runtime.compatible_finetune_compiler(
                str(active.get("compiler", ""))
            )
        )
        compiler_name = str(compiler_info.get("name", ""))
        if not compiler_name:
            return {
                "ok": False,
                "error": "No compatible finetune compiler is available.",
            }
        if not compiler_info.get("supports_local_sdk", True):
            return {
                "ok": False,
                "error": "Selected compiler does not support the local SDK.",
            }
        rule = self._rule_from(rule_id, project_root, source)
        if rule is None or not rule.spec:
            return {"ok": False, "error": "Rule has no PAW specification."}
        with self._finetune_lock:
            existing = self._finetune_jobs.get(rule_id)
            if existing and existing.get("status") in ("building", "ready"):
                if (
                    str(existing.get("behavior_hash", "")) == source_behavior_hash
                    and str(existing.get("compiler", "")) == compiler_name
                    and str(existing.get("compiler_snapshot", ""))
                    == str(compiler_info.get("latest_snapshot", ""))
                ):
                    return {"ok": True, "job": dict(existing)}
                existing["status"] = "cancelled"
                existing["stale"] = True
                existing["finished_at"] = time.time()
            job = {
                "id": secrets.token_urlsafe(16),
                "rule_id": rule_id,
                "rule_name": rule.title,
                "project_root": project_root,
                "source_hash": source_hash,
                "behavior_hash": source_behavior_hash,
                "source_path": source_path,
                "source": source,
                "spec": rule.spec,
                "validation_cases": cases,
                "status": "building",
                "compiler": compiler_name,
                "compiler_info": compiler_info,
                "compiler_snapshot": str(compiler_info.get("latest_snapshot", "")),
                "program_id": "",
                "error": "",
                "started_at": time.time(),
                "finished_at": None,
            }
            self._finetune_jobs[rule_id] = job
        self.work.submit(self._run_finetune, rule_id, job["id"])
        return {"ok": True, "job": dict(job)}

    def _run_finetune(self, rule_id: str, job_id: str) -> None:
        with self._finetune_lock:
            job = dict(self._finetune_jobs.get(rule_id) or {})
        if job.get("id") != job_id or job.get("status") != "building":
            return
        compiled = self._compile_program_for_snapshot(
            str(job.get("spec", "")),
            str(job.get("compiler", "")),
            str(job.get("compiler_snapshot", "")),
            timeout=(
                360
                if (job.get("compiler_info") or {}).get("compiler_kind")
                == "finetune_lora"
                else None
            ),
        )
        program_id = str(compiled.get("program_id", ""))
        with self._finetune_lock:
            current = self._finetune_jobs.get(rule_id)
            if not current or current.get("id") != job_id:
                return
            if current.get("status") != "building":
                return
            current["finished_at"] = time.time()
            if program_id:
                current["status"] = "ready"
                current["program_id"] = program_id
                current["compiler_snapshot"] = str(
                    compiled.get("compiler_snapshot", "")
                )
                current["validation"] = {
                    "ok": True,
                    "passed": 0,
                    "total": 0,
                    "results": [],
                    "note": "Validation cases run only when requested.",
                }
            else:
                current["status"] = "failed"
                current["error"] = str(
                    compiled.get("error", "Finetuned compilation failed or timed out.")
                )
            queued_job = dict(current)
        self._resume_queued_deployment_for_job(rule_id, queued_job)

    @staticmethod
    def _public_deployment_queue(value: dict[str, Any] | None) -> dict[str, Any]:
        if not value:
            return {}
        allowed = {
            "id",
            "kind",
            "rule_id",
            "project_root",
            "source_hash",
            "compiler",
            "compiler_mode",
            "behavior_hash",
            "compiler_snapshot",
            "program_id",
            "status",
            "phase",
            "error",
            "requested_compiler",
            "requested_compiler_snapshot",
            "requested_program_id",
            "validation_hash",
            "spec_hash",
            "case_count",
            "intent_hash",
            "coverage",
            "created_at",
            "updated_at",
            "finished_at",
            "result",
        }
        return {key: item for key, item in value.items() if key in allowed}

    @staticmethod
    def _coverage_identity(value: dict[str, Any] | None) -> dict[str, Any]:
        coverage = dict(value or {})
        mode = str(coverage.get("mode", "selected"))
        return {
            "mode": mode,
            "selected_projects": (
                []
                if mode == "all"
                else sorted(
                    {
                        str(root)
                        for root in coverage.get("selected_projects") or []
                        if root
                    }
                )
            ),
        }

    def _complete_deployment_if_active(
        self, queue_id: str, queued: dict[str, Any]
    ) -> bool:
        """Recognize a post-commit restart without racing rule mutations."""
        rule_id = str(queued.get("rule_id", ""))
        project_root = str(queued.get("project_root", ""))
        with rules_api.rule_mutation_transaction():
            current = rules_api.get_rule(rule_id, project_root or None) or {}
            active = current.get("active") or {}
            roots = [item["path"] for item in self._project_catalog()]
            coverage = rules_api.rule_coverage(rule_id, roots)
            if not (
                str(active.get("behavior_hash", ""))
                == str(queued.get("behavior_hash", ""))
                and str(active.get("compiler", "")) == str(queued.get("compiler", ""))
                and (
                    not queued.get("compiler_snapshot")
                    or str(active.get("compiler_snapshot", ""))
                    == str(queued.get("compiler_snapshot", ""))
                )
                and str(
                    active.get("compiler_mode") or revisions.AUTOMATIC_COMPILER_MODE
                )
                == str(queued.get("compiler_mode") or revisions.AUTOMATIC_COMPILER_MODE)
                and str(current.get("working_hash", ""))
                == str(queued.get("source_hash", ""))
                and self._coverage_identity(coverage)
                == self._coverage_identity(queued.get("coverage"))
            ):
                return False
            result = {
                "ok": True,
                "active": active,
                "rule": current,
                "coverage": coverage,
            }
            self.deployment_queue.compare_and_update(
                queue_id,
                deployment_queue.PENDING_STATUSES,
                status="succeeded",
                phase="Deployed",
                error="",
                result=result,
                finished_at=time.time(),
            )
            return True

    def queue_deployment(self, req: dict[str, Any]) -> dict[str, Any]:
        with self._workflow_admission_lock:
            return self._queue_deployment(req)

    def _queue_deployment(self, req: dict[str, Any]) -> dict[str, Any]:
        rule_id = str(req.get("rule_id", ""))
        project_root = str(req.get("project_root", ""))
        source = str(req.get("source", ""))
        valid, error = rules_api.validate_editor_source(source)
        if not valid:
            return {"ok": False, "error": error}
        projection = rules_api.source_projection(source)
        if projection.get("id") != rule_id:
            return {"ok": False, "error": "source ID does not match the rule"}
        source_hash = revisions.hash_source(source)
        source_behavior_hash = revisions.behavior_hash(source)
        current = rules_api.get_rule(rule_id, project_root or None) or {}
        current_active = current.get("active") or {}
        requested_compiler = str(req.get("compiler", ""))
        compiler_mode = str(
            req.get("compiler_mode")
            or (revisions.EXPLICIT_COMPILER_MODE if requested_compiler else "")
            or current_active.get("compiler_mode")
            or revisions.AUTOMATIC_COMPILER_MODE
        )
        if compiler_mode not in revisions.COMPILER_MODES:
            return {"ok": False, "error": "invalid compiler mode"}
        compiler = requested_compiler
        if compiler_mode == revisions.AUTOMATIC_COMPILER_MODE:
            if str(
                current_active.get("behavior_hash", "")
            ) == source_behavior_hash and current_active.get("program_id"):
                compiler = str(current_active.get("compiler", "")) or compiler
            else:
                automatic = self._automatic_base_compiler()
                compiler = str(automatic.get("name", "")) or compiler
        intent_coverage = self._coverage_identity(req.get("coverage"))
        deployment_intent_hash = hashlib.sha256(
            json.dumps(
                {
                    "rule_id": rule_id,
                    "project_root": project_root,
                    "source_hash": source_hash,
                    "compiler": requested_compiler,
                    "compiler_mode": compiler_mode,
                    "compiler_snapshot": str(req.get("compiler_snapshot", "")),
                    "program_id": str(req.get("program_id", "")),
                    "coverage": intent_coverage,
                    "warnings": list(req.get("warnings") or []),
                    "expected_active_hash": str(req.get("expected_active_hash", "")),
                },
                sort_keys=True,
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        queue_id = str(req.get("deployment_id") or secrets.token_urlsafe(18))
        existing_id = self.deployment_queue.get(queue_id)
        if existing_id:
            if (
                existing_id.get("intent_hash")
                and str(existing_id.get("intent_hash", "")) != deployment_intent_hash
            ) or (
                not existing_id.get("intent_hash")
                and (
                    str(existing_id.get("rule_id", "")) != rule_id
                    or str(existing_id.get("source_hash", "")) != source_hash
                    or str(existing_id.get("compiler", "")) != compiler
                    or str(existing_id.get("compiler_mode", "")) != compiler_mode
                )
            ):
                return {
                    "ok": False,
                    "error": "Deployment ID already belongs to another draft.",
                    "conflict": True,
                }
            return {
                "ok": True,
                "queue": self._public_deployment_queue(existing_id),
                "idempotent": True,
            }
        with self._finetune_lock:
            job = dict(self._finetune_jobs.get(rule_id) or {})
        job_matches = bool(
            str(job.get("behavior_hash", "")) == source_behavior_hash
            and str(job.get("compiler", "")) == compiler
            and (
                not req.get("compiler_snapshot")
                or str(job.get("compiler_snapshot", ""))
                == str(req.get("compiler_snapshot", ""))
            )
            and job.get("status") in ("building", "ready")
        )
        if not current:
            saved = rules_api.save_library_draft(rule_id, source, expected_absent=True)
            if not saved.get("ok"):
                return saved
            rules_api.save_validation_cases(
                str(saved.get("path", "")),
                list(req.get("validation_cases") or []),
            )
            draft_coverage = dict(req.get("coverage") or {})
            draft_coverage.update(
                {
                    "compiler": compiler,
                    "compiler_mode": compiler_mode,
                    "compiler_snapshot": str(req.get("compiler_snapshot", "")),
                }
            )
            rules_api.save_deployment_coverage_draft(rule_id, draft_coverage)
            current = rules_api.get_rule(rule_id, None) or {}
        current_definition = current.get("definition") or {}
        current_active = current.get("active") or current_active
        expected_active_hash = str(
            req.get(
                "expected_active_hash",
                current_active.get("source_hash", ""),
            )
        )
        if str(current_active.get("source_hash", "")) != expected_active_hash:
            return {
                "ok": False,
                "error": "The deployed revision changed; review the draft again.",
            }
        rule = self._rule_from(rule_id, project_root, source)
        if rule is None:
            return {"ok": False, "error": "Queued rule could not be loaded."}
        compiler_info = self.runtime.compiler_info(compiler)
        requested_snapshot = str(req.get("compiler_snapshot", ""))
        current_snapshot = str(compiler_info.get("latest_snapshot", ""))
        requested_program = str(req.get("program_id", ""))
        cached_program = getattr(self.runtime, "cached_program_id_for_spec", None)
        cached_program_id = (
            str(cached_program(rule.spec, compiler or None) or "")
            if (
                callable(cached_program)
                and (not requested_snapshot or requested_snapshot == current_snapshot)
            )
            else ""
        )
        active_program = ""
        active_compiler = str(
            current_active.get("compiler")
            or self.runtime.compiler_info("").get("name", "")
        )
        if (
            str(current_active.get("behavior_hash", "")) == source_behavior_hash
            and active_compiler == compiler
            and (
                not requested_snapshot
                or str(current_active.get("compiler_snapshot", ""))
                == requested_snapshot
            )
        ):
            active_program = str(current_active.get("program_id", ""))
        artifacts = [
            dict(artifact)
            for artifact in (
                (current_active.get("artifacts") or {}).values()
                if isinstance(current_active.get("artifacts"), dict)
                else []
            )
            if isinstance(artifact, dict)
            and str(artifact.get("behavior_hash", "")) == source_behavior_hash
            and str(artifact.get("compiler", "")) == compiler
            and (
                not requested_snapshot
                or str(artifact.get("compiler_snapshot", "")) == requested_snapshot
            )
            and artifact.get("program_id")
        ]
        artifact = max(
            artifacts,
            key=lambda item: float(item.get("created_at", 0) or 0),
            default={},
        )
        artifact_program = str(artifact.get("program_id", ""))
        requested_artifact = next(
            (
                item
                for item in artifacts
                if str(item.get("program_id", "")) == requested_program
            ),
            {},
        )
        program_id = ""
        if job_matches and job.get("status") == "ready":
            program_id = str(job.get("program_id", ""))
        elif requested_program and (
            requested_program in (cached_program_id, active_program)
            or requested_artifact
        ):
            program_id = requested_program
        elif cached_program_id:
            program_id = cached_program_id
        elif active_program:
            program_id = active_program
        elif artifact_program:
            program_id = artifact_program
        if (
            not program_id
            and requested_snapshot
            and requested_snapshot != current_snapshot
        ):
            return {
                "ok": False,
                "error": (
                    "The selected compiler changed. Choose it again before "
                    "deploying this draft."
                ),
                "compiler_catalog_stale": True,
            }
        existing = self.deployment_queue.active_for_rule(rule_id)
        if existing:
            cancelled = self.deployment_queue.cancel(
                str(existing.get("id", "")),
                "Superseded by a newer deployment request.",
                expected_statuses=(deployment_queue.CANCELLABLE_DEPLOYMENT_STATUSES),
            )
            if cancelled is None:
                return {
                    "ok": False,
                    "error": (
                        "The previous deployment is already committing. "
                        "Wait for it to finish, then deploy this draft."
                    ),
                }
        waiting_for_build = bool(job_matches and job.get("status") == "building")
        initial_status = (
            "waiting_for_build"
            if waiting_for_build
            else ("checking" if program_id else "building")
        )
        queue_value = self.deployment_queue.put(
            {
                "id": queue_id,
                "kind": deployment_queue.DEPLOYMENT_KIND,
                "rule_id": rule_id,
                "project_root": project_root,
                "source": source,
                "source_hash": source_hash,
                "behavior_hash": source_behavior_hash,
                "intent_hash": deployment_intent_hash,
                "compiler": compiler,
                "compiler_mode": compiler_mode,
                "requested_compiler": requested_compiler,
                "requested_compiler_snapshot": str(req.get("compiler_snapshot", "")),
                "requested_program_id": requested_program,
                "compiler_snapshot": str(
                    (
                        current_active.get("compiler_snapshot", "")
                        if (
                            compiler_mode == revisions.AUTOMATIC_COMPILER_MODE
                            and str(current_active.get("behavior_hash", ""))
                            == source_behavior_hash
                            and compiler == str(current_active.get("compiler", ""))
                        )
                        else req.get("compiler_snapshot")
                    )
                    or requested_artifact.get("compiler_snapshot", "")
                    or (job.get("compiler_snapshot", "") if job_matches else "")
                    or artifact.get("compiler_snapshot", "")
                    or compiler_info.get("latest_snapshot", "")
                ),
                "program_id": program_id,
                "validation_cases": rules_api.normalize_validation_cases(
                    list(req.get("validation_cases") or [])
                ),
                "coverage": intent_coverage,
                "warnings": list(req.get("warnings") or []),
                "expected_active_hash": expected_active_hash,
                "expected_definition_hash": str(
                    current_definition.get("source_hash", "")
                ),
                "status": initial_status,
                "phase": (
                    "Building compiler"
                    if initial_status in ("waiting_for_build", "building")
                    else "Checking draft"
                ),
                "error": "",
            }
        )
        if not waiting_for_build:
            self._schedule_queued_deployment(queue_id)
        _log(
            f"deployment {queue_id} queued rule={rule_id} "
            f"compiler={compiler} status={initial_status}"
        )
        return {
            "ok": True,
            "queue": self._public_deployment_queue(queue_value),
        }

    def deployment_queue_status(
        self, rule_id: str, queue_id: str = ""
    ) -> dict[str, Any]:
        value = (
            self.deployment_queue.get(queue_id)
            if queue_id
            else (
                self.deployment_queue.active_for_rule(rule_id)
                or self.deployment_queue.latest_for_rule(rule_id)
            )
        )
        if value and (
            str(value.get("rule_id", "")) != rule_id
            or str(value.get("kind") or deployment_queue.DEPLOYMENT_KIND)
            != deployment_queue.DEPLOYMENT_KIND
        ):
            value = None
        return {
            "ok": True,
            "queue": self._public_deployment_queue(value),
        }

    def cancel_queued_deployment(
        self,
        rule_id: str,
        reason: str = "Cancelled by user.",
        queue_id: str = "",
    ) -> dict[str, Any]:
        value = (
            self.deployment_queue.get(queue_id)
            if queue_id
            else self.deployment_queue.active_for_rule(rule_id)
        )
        if value and (
            str(value.get("rule_id", "")) != rule_id
            or str(value.get("kind") or deployment_queue.DEPLOYMENT_KIND)
            != deployment_queue.DEPLOYMENT_KIND
        ):
            value = None
        if not value:
            return {"ok": False, "error": "No deployment is queued."}
        cancelled = self.deployment_queue.cancel(
            str(value.get("id", "")),
            reason,
            expected_statuses=(deployment_queue.CANCELLABLE_DEPLOYMENT_STATUSES),
        )
        if cancelled is None:
            return {
                "ok": False,
                "error": "This deployment can no longer be cancelled.",
                "queue": self._public_deployment_queue(
                    self.deployment_queue.get(str(value.get("id", "")))
                ),
            }
        return {
            "ok": True,
            "queue": self._public_deployment_queue(cancelled),
        }

    def queue_validation(self, req: dict[str, Any]) -> dict[str, Any]:
        with self._workflow_admission_lock:
            return self._queue_validation(req)

    def _queue_validation(self, req: dict[str, Any]) -> dict[str, Any]:
        rule_id = str(req.get("rule_id", ""))
        project_root = str(req.get("project_root", ""))
        source = str(req.get("source", ""))
        valid, error = rules_api.validate_editor_source(source)
        if not valid:
            return {"ok": False, "error": error}
        projection = rules_api.source_projection(source)
        if projection.get("id") != rule_id:
            return {"ok": False, "error": "source ID does not match the rule"}
        rule = self._rule_from(rule_id, project_root, source)
        if rule is None or not rule.spec:
            return {"ok": False, "error": "Rule has no PAW specification."}
        cases = rules_api.normalize_validation_cases(
            list(req.get("validation_cases") or [])
        )
        if not cases:
            return {"ok": False, "error": "Add at least one validation case."}
        compiler_info = self.runtime.compiler_info(str(req.get("compiler", "")))
        compiler = str(req.get("compiler") or compiler_info.get("name", ""))
        compiler_snapshot = str(
            req.get("compiler_snapshot") or compiler_info.get("latest_snapshot", "")
        )
        source_hash = revisions.hash_source(source)
        spec_hash = validation_store.spec_fingerprint(rule.spec)
        validation_hash = hashlib.sha256(
            json.dumps(
                {
                    "rule_id": rule_id,
                    "project_root": project_root,
                    "spec_hash": spec_hash,
                    "compiler": compiler,
                    "compiler_snapshot": compiler_snapshot,
                    "cases": sorted(
                        (
                            str(case.get("input", "")),
                            str(case.get("expected", "")),
                        )
                        for case in cases
                    ),
                },
                sort_keys=True,
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        queue_id = str(req.get("validation_id") or secrets.token_urlsafe(18))
        existing_id = self.deployment_queue.get(queue_id)
        if existing_id:
            if (
                str(existing_id.get("kind", "")) != deployment_queue.VALIDATION_KIND
                or str(existing_id.get("validation_hash", "")) != validation_hash
            ):
                return {
                    "ok": False,
                    "error": "Validation ID already belongs to another run.",
                    "conflict": True,
                }
            return {
                "ok": True,
                "queue": self._public_deployment_queue(existing_id),
                "idempotent": True,
            }
        target = self._validation_target(
            rule_id,
            project_root,
            rule,
            compiler,
            str(req.get("program_id", "")),
            compiler_snapshot,
        )
        program_id = str(target.get("program_id", ""))
        compiler = str(target.get("compiler") or compiler)
        compiler_snapshot = str(target.get("compiler_snapshot") or compiler_snapshot)
        requested_snapshot = str(req.get("compiler_snapshot", ""))
        current_snapshot = str(compiler_info.get("latest_snapshot", ""))
        if (
            not program_id
            and requested_snapshot
            and requested_snapshot != current_snapshot
        ):
            return {
                "ok": False,
                "error": (
                    "The selected compiler changed. Choose it again before "
                    "running these tests."
                ),
                "compiler_catalog_stale": True,
            }
        existing = self.deployment_queue.active_for_rule(
            rule_id, kind=deployment_queue.VALIDATION_KIND
        )
        if existing:
            self.deployment_queue.cancel(
                str(existing.get("id", "")),
                "Superseded by a newer validation request.",
            )
        queue_value = self.deployment_queue.put(
            {
                "id": queue_id,
                "kind": deployment_queue.VALIDATION_KIND,
                "rule_id": rule_id,
                "project_root": project_root,
                "source": source,
                "source_hash": source_hash,
                "behavior_hash": revisions.behavior_hash(source),
                "validation_hash": validation_hash,
                "spec_hash": spec_hash,
                "case_count": len(cases),
                "validation_cases": cases,
                "compiler": compiler,
                "compiler_snapshot": compiler_snapshot,
                "program_id": program_id,
                "status": "validating" if program_id else "building",
                "phase": "Running tests" if program_id else "Building compiler",
                "error": "",
            }
        )
        self.work.submit(self._run_queued_validation, queue_id)
        return {
            "ok": True,
            "queue": self._public_deployment_queue(queue_value),
        }

    def validation_queue_status(
        self, rule_id: str, queue_id: str = ""
    ) -> dict[str, Any]:
        value = (
            self.deployment_queue.get(queue_id)
            if queue_id
            else (
                self.deployment_queue.active_for_rule(
                    rule_id, kind=deployment_queue.VALIDATION_KIND
                )
                or self.deployment_queue.latest_for_rule(
                    rule_id, kind=deployment_queue.VALIDATION_KIND
                )
            )
        )
        if value and (
            str(value.get("rule_id", "")) != rule_id
            or str(value.get("kind", "")) != deployment_queue.VALIDATION_KIND
        ):
            value = None
        return {
            "ok": True,
            "queue": self._public_deployment_queue(value),
        }

    def cancel_queued_validation(
        self,
        rule_id: str,
        reason: str = "Cancelled by user.",
        queue_id: str = "",
    ) -> dict[str, Any]:
        value = (
            self.deployment_queue.get(queue_id)
            if queue_id
            else self.deployment_queue.active_for_rule(
                rule_id, kind=deployment_queue.VALIDATION_KIND
            )
        )
        if value and (
            str(value.get("rule_id", "")) != rule_id
            or str(value.get("kind", "")) != deployment_queue.VALIDATION_KIND
        ):
            value = None
        if not value:
            return {"ok": False, "error": "No validation run is queued."}
        cancelled = self.deployment_queue.cancel(str(value.get("id", "")), reason)
        if cancelled is None:
            return {
                "ok": False,
                "error": "This validation run is no longer cancellable.",
                "queue": self._public_deployment_queue(
                    self.deployment_queue.get(str(value.get("id", "")))
                ),
            }
        return {
            "ok": True,
            "queue": self._public_deployment_queue(cancelled),
        }

    def _run_queued_validation(self, queue_id: str) -> None:
        if not queue_id:
            return
        with self._queued_validation_lock:
            if queue_id in self._queued_validations_running:
                return
            self._queued_validations_running.add(queue_id)
        try:
            queued = self.deployment_queue.get(queue_id)
            if (
                not queued
                or str(queued.get("kind", "")) != deployment_queue.VALIDATION_KIND
                or queued.get("status") not in deployment_queue.PENDING_STATUSES
            ):
                return
            rule_id = str(queued.get("rule_id", ""))
            project_root = str(queued.get("project_root", ""))
            source = str(queued.get("source", ""))
            rule = self._rule_from(rule_id, project_root, source)
            if rule is None or not rule.spec:
                self.deployment_queue.compare_and_update(
                    queue_id,
                    deployment_queue.PENDING_STATUSES,
                    status="failed",
                    phase="Invalid draft",
                    error="The queued rule could not be loaded.",
                    finished_at=time.time(),
                )
                return
            compiler = str(queued.get("compiler", ""))
            compiler_info = self.runtime.compiler_info(compiler)
            program_id = str(queued.get("program_id", ""))
            requested_snapshot = str(queued.get("compiler_snapshot", ""))
            current_snapshot = str(compiler_info.get("latest_snapshot", ""))
            resolved_snapshot = requested_snapshot or current_snapshot
            if not program_id:
                claimed = self.deployment_queue.compare_and_update(
                    queue_id,
                    deployment_queue.PENDING_STATUSES,
                    status="building",
                    phase="Building compiler",
                )
                if claimed is None:
                    return
                compiled = self._compile_program_for_snapshot(
                    rule.spec,
                    compiler,
                    requested_snapshot,
                    timeout=(
                        360
                        if compiler_info.get("compiler_kind") == "finetune_lora"
                        else None
                    ),
                )
                if not compiled.get("ok"):
                    self.deployment_queue.compare_and_update(
                        queue_id,
                        {"building"},
                        status="failed",
                        phase=(
                            "Compiler changed"
                            if compiled.get("compiler_catalog_stale")
                            else "Compiler failed"
                        ),
                        error=str(
                            compiled.get(
                                "error",
                                "The compiler build failed or timed out.",
                            )
                        ),
                        finished_at=time.time(),
                    )
                    return
                program_id = str(compiled.get("program_id", ""))
                resolved_snapshot = str(compiled.get("compiler_snapshot", ""))
                running = self.deployment_queue.compare_and_update(
                    queue_id,
                    {"building"},
                    program_id=program_id,
                    compiler_snapshot=resolved_snapshot,
                    status="validating",
                    phase="Running tests",
                )
                if running is None:
                    return
            else:
                running = self.deployment_queue.compare_and_update(
                    queue_id,
                    deployment_queue.PENDING_STATUSES,
                    status="validating",
                    phase="Running tests",
                )
                if running is None:
                    return
            result = self.validate_rule_cases(
                rule_id,
                project_root,
                source,
                list(queued.get("validation_cases") or []),
                compiler,
                resolved_snapshot,
                program_id,
            )
            self.deployment_queue.compare_and_update(
                queue_id,
                {"validating"},
                status="succeeded" if result.get("ok") else "failed",
                phase="Tests complete" if result.get("ok") else "Tests failed",
                error=""
                if result.get("ok")
                else str(result.get("error", "Validation failed.")),
                result=result if result.get("ok") else {},
                finished_at=time.time(),
            )
        except Exception as exc:
            traceback.print_exc()
            self.deployment_queue.compare_and_update(
                queue_id,
                deployment_queue.PENDING_STATUSES,
                status="failed",
                phase="Internal error",
                error=f"{type(exc).__name__}: {exc}",
                finished_at=time.time(),
            )
        finally:
            with self._queued_validation_lock:
                self._queued_validations_running.discard(queue_id)

    def _resume_queued_deployment_for_job(
        self, rule_id: str, job: dict[str, Any]
    ) -> None:
        queued = self.deployment_queue.active_for_rule(rule_id)
        if not queued:
            return
        if (
            str(queued.get("behavior_hash", "")) != str(job.get("behavior_hash", ""))
            or str(queued.get("compiler", "")) != str(job.get("compiler", ""))
            or (
                queued.get("compiler_snapshot")
                and str(queued.get("compiler_snapshot", ""))
                != str(job.get("compiler_snapshot", ""))
            )
        ):
            return
        if job.get("status") == "ready":
            resumed = self.deployment_queue.compare_and_update(
                str(queued["id"]),
                {"waiting_for_build", "building"},
                status="checking",
                phase="Checking draft",
                program_id=str(job.get("program_id", "")),
                compiler_snapshot=str(job.get("compiler_snapshot", "")),
            )
            if resumed is not None:
                self._schedule_queued_deployment(str(queued["id"]))
        elif job.get("status") == "failed":
            self.deployment_queue.compare_and_update(
                str(queued["id"]),
                {"waiting_for_build", "building"},
                status="failed",
                phase="Compiler failed",
                error=str(job.get("error", "Compiler build failed.")),
                finished_at=time.time(),
            )

    def _schedule_queued_deployment(self, queue_id: str, delay: float = 0.25) -> None:
        def submit():
            self.work.submit(self._run_queued_deployment, queue_id)

        timer = threading.Timer(delay, submit)
        timer.daemon = True
        timer.start()

    def _run_queued_deployment(self, queue_id: str) -> None:
        if not queue_id:
            return
        with self._queued_deployment_lock:
            if queue_id in self._queued_deployments_running:
                return
            self._queued_deployments_running.add(queue_id)
        try:
            queued = self.deployment_queue.get(queue_id)
            if (
                not queued
                or queued.get("status") not in deployment_queue.PENDING_STATUSES
            ):
                return
            rule_id = str(queued.get("rule_id", ""))
            project_root = str(queued.get("project_root", ""))
            source = str(queued.get("source", ""))
            _log(
                f"deployment {queue_id} started rule={rule_id} "
                f"status={queued.get('status', '')}"
            )
            if self._complete_deployment_if_active(queue_id, queued):
                return
            rule = self._rule_from(rule_id, project_root, source)
            if rule is None or not rule.spec:
                self.deployment_queue.compare_and_update(
                    queue_id,
                    deployment_queue.PENDING_STATUSES,
                    status="failed",
                    phase="Invalid draft",
                    error="The queued rule could not be loaded.",
                    finished_at=time.time(),
                )
                return
            program_id = str(queued.get("program_id", ""))
            if not program_id:
                claimed = self.deployment_queue.compare_and_update(
                    queue_id,
                    deployment_queue.PENDING_STATUSES,
                    status="building",
                    phase="Building compiler",
                )
                if claimed is None:
                    return
                compiler_info = self.runtime.compiler_info(
                    str(queued.get("compiler", ""))
                )
                requested_snapshot = str(queued.get("compiler_snapshot", ""))
                compiled = self._compile_program_for_snapshot(
                    rule.spec,
                    str(queued.get("compiler", "")),
                    requested_snapshot,
                    timeout=(
                        360
                        if compiler_info.get("compiler_kind") == "finetune_lora"
                        else None
                    ),
                )
                if not compiled.get("ok"):
                    self.deployment_queue.compare_and_update(
                        queue_id,
                        {"building"},
                        status="failed",
                        phase=(
                            "Compiler changed"
                            if compiled.get("compiler_catalog_stale")
                            else "Compiler failed"
                        ),
                        error=str(
                            compiled.get(
                                "error",
                                "The compiler build failed or timed out.",
                            )
                        ),
                        finished_at=time.time(),
                    )
                    return
                program_id = str(compiled.get("program_id", ""))
                queued = self.deployment_queue.compare_and_update(
                    queue_id,
                    {"building"},
                    program_id=program_id,
                    compiler_snapshot=str(compiled.get("compiler_snapshot", "")),
                    status="checking",
                    phase="Checking draft",
                )
                if queued is None:
                    return
            else:
                queued = self.deployment_queue.compare_and_update(
                    queue_id,
                    deployment_queue.PENDING_STATUSES,
                    status="checking",
                    phase="Checking draft",
                )
                if queued is None:
                    return
            warming = self.deployment_queue.compare_and_update(
                queue_id,
                {"checking"},
                status="checking",
                phase="Warming compiler",
            )
            if warming is None:
                return
            if not self.runtime.warm(program_id):
                self.deployment_queue.compare_and_update(
                    queue_id,
                    {"checking"},
                    status="failed",
                    phase="Warmup failed",
                    error=(
                        "The compiled program could not be loaded locally. "
                        "The previous deployment remains active."
                    ),
                    finished_at=time.time(),
                )
                return
            queued = warming
            current = rules_api.get_rule(rule_id, project_root or None) or {}
            definition = current.get("definition") or {}
            active = current.get("active") or {}
            if str(definition.get("source_hash", "")) != str(
                queued.get("expected_definition_hash", "")
            ) or str(active.get("source_hash", "")) != str(
                queued.get("expected_active_hash", "")
            ):
                self.deployment_queue.compare_and_update(
                    queue_id,
                    {"checking"},
                    status="cancelled",
                    phase="Draft changed",
                    error="The rule changed after deployment was queued.",
                    finished_at=time.time(),
                )
                return
            definition_path = str(definition.get("source_path", ""))
            deployment_cases = (
                rules_api.validation_cases_for_path(definition_path)
                if definition_path
                else list(queued.get("validation_cases") or [])
            )
            prepared = self.prepare_rule_deployment(
                {
                    "rule_id": rule_id,
                    "project_root": project_root,
                    "source": source,
                    "source_changed": (
                        str(queued.get("source_hash", ""))
                        != str(active.get("source_hash", ""))
                    ),
                    "expected_active_hash": str(queued.get("expected_active_hash", "")),
                    "compiler": str(queued.get("compiler", "")),
                    "compiler_mode": str(
                        queued.get("compiler_mode") or revisions.AUTOMATIC_COMPILER_MODE
                    ),
                    "compiler_snapshot": str(queued.get("compiler_snapshot", "")),
                    "program_id": program_id,
                    "coverage": dict(queued.get("coverage") or {}),
                    "warnings": list(queued.get("warnings") or []),
                    "validation_cases": deployment_cases,
                    "validation_cases_from_working_copy": bool(definition_path),
                }
            )
            if not prepared.get("ok"):
                self.deployment_queue.compare_and_update(
                    queue_id,
                    {"checking"},
                    status="failed",
                    phase="Deployment failed",
                    error=str(prepared.get("error", "Deployment preparation failed.")),
                    result={},
                    finished_at=time.time(),
                )
                _log(
                    f"deployment {queue_id} failed phase=prepare "
                    f"error={prepared.get('error', '')}"
                )
                return
            deploying = self.deployment_queue.compare_and_update(
                queue_id,
                {"checking"},
                status="deploying",
                phase="Deploying",
            )
            if deploying is None:
                with self._state_lock:
                    self._prepared_deployments.pop(str(prepared.get("token", "")), None)
                return
            result = self.commit_rule_deployment(str(prepared["token"]))
            self.deployment_queue.compare_and_update(
                queue_id,
                {"deploying"},
                status="succeeded" if result.get("ok") else "failed",
                phase="Deployed" if result.get("ok") else "Deployment failed",
                error=""
                if result.get("ok")
                else str(result.get("error", "Deployment failed.")),
                result=result,
                finished_at=time.time(),
            )
            _log(
                f"deployment {queue_id} "
                f"{'succeeded' if result.get('ok') else 'failed'} "
                f"phase=commit error={result.get('error', '')}"
            )
        except Exception as exc:
            traceback.print_exc()
            self.deployment_queue.compare_and_update(
                queue_id,
                deployment_queue.PENDING_STATUSES,
                status="failed",
                phase="Internal error",
                error=f"{type(exc).__name__}: {exc}",
                finished_at=time.time(),
            )
            _log(f"deployment {queue_id} crashed error={type(exc).__name__}: {exc}")
        finally:
            with self._queued_deployment_lock:
                self._queued_deployments_running.discard(queue_id)

    def _queue_automatic_optimization(
        self,
        *,
        rule_id: str,
        project_root: str,
        source_path: str,
        source: str,
        active: dict[str, Any],
    ) -> dict[str, Any]:
        existing = self.deployment_queue.active_for_rule(
            rule_id, kind=deployment_queue.OPTIMIZATION_KIND
        )
        if (
            str(active.get("compiler_mode") or revisions.AUTOMATIC_COMPILER_MODE)
            != revisions.AUTOMATIC_COMPILER_MODE
        ):
            if existing:
                self.deployment_queue.cancel(
                    str(existing.get("id", "")),
                    "Automatic optimization was disabled.",
                    expected_statuses=(
                        deployment_queue.CANCELLABLE_DEPLOYMENT_STATUSES
                    ),
                )
            return {}
        active_compiler = str(active.get("compiler", ""))
        active_info = self.runtime.compiler_info(active_compiler)
        if active_info.get("compiler_kind") == "finetune_lora":
            return {}
        target = self.runtime.compatible_finetune_compiler(active_compiler)
        target_compiler = str(target.get("name", ""))
        target_snapshot = str(target.get("latest_snapshot", ""))
        if not target_compiler or not target.get("supports_local_sdk", True):
            return {}
        rule = self._rule_from(rule_id, project_root, source)
        if rule is None or not rule.spec:
            return {}
        behavior_hash = str(
            active.get("behavior_hash") or revisions.behavior_hash(source)
        )
        queue_id = (
            "opt-"
            + hashlib.sha256(
                "\x00".join(
                    (
                        rule_id,
                        behavior_hash,
                        target_compiler,
                        target_snapshot,
                    )
                ).encode("utf-8")
            ).hexdigest()[:24]
        )
        previous = self.deployment_queue.get(queue_id)
        if previous and previous.get("status") in deployment_queue.PENDING_STATUSES:
            return self._public_deployment_queue(previous)
        if previous and previous.get("status") == "succeeded":
            artifact = next(
                (
                    dict(item)
                    for item in (active.get("artifacts") or {}).values()
                    if isinstance(item, dict)
                    and str(item.get("compiler", "")) == target_compiler
                    and str(item.get("compiler_snapshot", "")) == target_snapshot
                    and item.get("program_id")
                ),
                {},
            )
            if artifact:
                promoted = revisions.activate_artifact(
                    rule_id,
                    source_path,
                    behavior_hash,
                    compiler=target_compiler,
                    program_id=str(artifact.get("program_id", "")),
                    compiler_snapshot=target_snapshot,
                    compiler_mode=revisions.AUTOMATIC_COMPILER_MODE,
                    expected_compiler_mode=revisions.AUTOMATIC_COMPILER_MODE,
                )
                if promoted:
                    self.rules_cache.invalidate()
                    self._warm_rule_consumers(rule_id, source_path)
                    refreshed = self.deployment_queue.update(
                        queue_id,
                        phase="Optimized",
                        result={"ok": True, "active": promoted},
                        finished_at=time.time(),
                    )
                    return self._public_deployment_queue(refreshed)
        if existing and str(existing.get("id", "")) != queue_id:
            self.deployment_queue.cancel(
                str(existing.get("id", "")),
                "Superseded by a newer deployed revision.",
                expected_statuses=(deployment_queue.CANCELLABLE_DEPLOYMENT_STATUSES),
            )
        queued = self.deployment_queue.put(
            {
                "id": queue_id,
                "kind": deployment_queue.OPTIMIZATION_KIND,
                "rule_id": rule_id,
                "project_root": project_root,
                "source_path": str(source_path),
                "source_hash": str(active.get("source_hash", "")),
                "behavior_hash": behavior_hash,
                "spec": rule.spec,
                "base_compiler": active_compiler,
                "compiler": target_compiler,
                "compiler_mode": revisions.AUTOMATIC_COMPILER_MODE,
                "compiler_snapshot": target_snapshot,
                "program_id": "",
                "status": "waiting_for_build",
                "phase": "Optimizing in background",
                "error": "",
            }
        )
        getattr(self, "optimization_work", self.work).submit(
            self._run_optimization, queue_id
        )
        return self._public_deployment_queue(queued)

    def _run_optimization(self, queue_id: str) -> None:
        if not queue_id:
            return
        with self._queued_deployment_lock:
            if queue_id in self._queued_deployments_running:
                return
            self._queued_deployments_running.add(queue_id)
        try:
            queued = self.deployment_queue.get(queue_id) or {}
            if (
                queued.get("kind") != deployment_queue.OPTIMIZATION_KIND
                or queued.get("status") not in deployment_queue.PENDING_STATUSES
            ):
                return
            rule_id = str(queued.get("rule_id", ""))
            source_path = str(queued.get("source_path", ""))
            active = revisions.active_info(rule_id, source_path) or {}
            if (
                str(active.get("behavior_hash", ""))
                != str(queued.get("behavior_hash", ""))
                or str(active.get("compiler_mode", ""))
                != revisions.AUTOMATIC_COMPILER_MODE
            ):
                self.deployment_queue.cancel(
                    queue_id,
                    "The deployed rule or compiler mode changed.",
                    expected_statuses=(
                        deployment_queue.CANCELLABLE_DEPLOYMENT_STATUSES
                    ),
                )
                return
            target_compiler = str(queued.get("compiler", ""))
            target_info = self.runtime.compiler_info(target_compiler)
            if (
                target_info.get("compiler_kind") != "finetune_lora"
                or not target_info.get("supports_local_sdk", True)
                or str(target_info.get("latest_snapshot", ""))
                != str(queued.get("compiler_snapshot", ""))
            ):
                self.deployment_queue.cancel(
                    queue_id,
                    "The compatible finetune compiler changed.",
                    expected_statuses=(
                        deployment_queue.CANCELLABLE_DEPLOYMENT_STATUSES
                    ),
                )
                return
            if str(active.get("compiler", "")) == target_compiler:
                self.deployment_queue.compare_and_update(
                    queue_id,
                    deployment_queue.PENDING_STATUSES,
                    status="succeeded",
                    phase="Optimized",
                    result={"ok": True, "active": active},
                    finished_at=time.time(),
                )
                return
            claimed = self.deployment_queue.compare_and_update(
                queue_id,
                deployment_queue.PENDING_STATUSES,
                status="building",
                phase="Optimizing in background",
            )
            if claimed is None:
                return
            compiled = self._compile_program_for_snapshot(
                str(queued.get("spec", "")),
                target_compiler,
                str(queued.get("compiler_snapshot", "")),
                timeout=360,
            )
            if not compiled.get("ok"):
                self.deployment_queue.compare_and_update(
                    queue_id,
                    {"building"},
                    status="failed",
                    phase=(
                        "Compiler changed"
                        if compiled.get("compiler_catalog_stale")
                        else "Optimization failed"
                    ),
                    error=str(
                        compiled.get(
                            "error",
                            "The finetuned compiler build failed or timed out.",
                        )
                    ),
                    finished_at=time.time(),
                )
                return
            program_id = str(compiled.get("program_id", ""))
            if not self.runtime.warm(program_id):
                self.deployment_queue.compare_and_update(
                    queue_id,
                    {"building"},
                    status="failed",
                    phase="Optimization failed",
                    error="The finetuned program could not be warmed locally.",
                    finished_at=time.time(),
                )
                return
            promoting = self.deployment_queue.compare_and_update(
                queue_id,
                {"building"},
                status="deploying",
                phase="Promoting optimized compiler",
                program_id=program_id,
            )
            if promoting is None:
                return
            with self._deployment_lock:
                promoted = revisions.activate_artifact(
                    rule_id,
                    source_path,
                    str(queued.get("behavior_hash", "")),
                    compiler=target_compiler,
                    program_id=program_id,
                    compiler_snapshot=str(queued.get("compiler_snapshot", "")),
                    compiler_mode=revisions.AUTOMATIC_COMPILER_MODE,
                    expected_compiler_mode=revisions.AUTOMATIC_COMPILER_MODE,
                )
            if not promoted:
                self.deployment_queue.compare_and_update(
                    queue_id,
                    {"deploying"},
                    status="cancelled",
                    error=("The deployed rule changed before optimization."),
                    finished_at=time.time(),
                )
                return
            self.rules_cache.invalidate()
            self._warm_rule_consumers(rule_id, source_path)
            self.deployment_queue.compare_and_update(
                queue_id,
                {"deploying"},
                program_id=program_id,
                status="succeeded",
                phase="Optimized",
                error="",
                result={"ok": True, "active": promoted},
                finished_at=time.time(),
            )
        except Exception as exc:
            traceback.print_exc()
            self.deployment_queue.compare_and_update(
                queue_id,
                deployment_queue.PENDING_STATUSES,
                status="failed",
                phase="Optimization failed",
                error=f"{type(exc).__name__}: {exc}",
                finished_at=time.time(),
            )
        finally:
            with self._queued_deployment_lock:
                self._queued_deployments_running.discard(queue_id)

    def _warm_rule_consumers(self, rule_id: str, source_path: str) -> None:
        canonical_path = str(Path(source_path).resolve())
        for project in self._project_catalog():
            root = str(project.get("path", ""))
            effective = rules_api.get_rule(rule_id, root)
            effective_path = str(
                ((effective or {}).get("definition") or {}).get("source_path", "")
            )
            if effective_path and str(Path(effective_path).resolve()) == canonical_path:
                with self._state_lock:
                    self._warmed.add(root)
                self.work.submit(self._warm, root)

    def finetune_status(self, rule_id: str, project_root: str) -> dict[str, Any]:
        info = rules_api.get_rule(rule_id, project_root or None) or {}
        active = dict(info.get("active") or {})
        with self._finetune_lock:
            job = dict(self._finetune_jobs.get(rule_id) or {})
        automatic = (
            self.deployment_queue.active_for_rule(
                rule_id, kind=deployment_queue.OPTIMIZATION_KIND
            )
            or self.deployment_queue.latest_for_rule(
                rule_id, kind=deployment_queue.OPTIMIZATION_KIND
            )
            or {}
        )
        if automatic and (
            not job
            or float(automatic.get("created_at", 0) or 0)
            >= float(job.get("started_at", 0) or 0)
        ):
            job = self._public_deployment_queue(automatic)
            job["automatic"] = True
            if job.get("status") == "succeeded":
                job["status"] = "activated"
        if job:
            job["stale"] = bool(
                active.get("behavior_hash")
                and str(active.get("behavior_hash")) != str(job.get("behavior_hash"))
            )
        return {
            "ok": True,
            "active": active,
            "job": job,
        }

    def cancel_finetune(self, rule_id: str) -> dict[str, Any]:
        with self._finetune_lock:
            job = self._finetune_jobs.get(rule_id)
            if not job or job.get("status") != "building":
                return {"ok": False, "error": "No finetune build is running."}
            job["status"] = "cancelled"
            job["finished_at"] = time.time()
        return {"ok": True}

    def _discard_stale_finetune_job(
        self, rule_id: str, active_behavior_hash: str
    ) -> bool:
        with self._finetune_lock:
            job = self._finetune_jobs.get(rule_id)
            if (
                not job
                or str(job.get("behavior_hash", "")) == active_behavior_hash
                or job.get("status") not in ("building", "ready")
            ):
                return False
            job["status"] = "cancelled"
            job["stale"] = True
            job["error"] = "Build discarded because a different revision was deployed."
            job["finished_at"] = time.time()
            return True

    def discard_finetune(self, rule_id: str) -> dict[str, Any]:
        with self._finetune_lock:
            job = self._finetune_jobs.get(rule_id)
            if not job or job.get("status") not in ("ready", "failed", "cancelled"):
                return {"ok": False, "error": "No finetuned build to discard."}
            self._finetune_jobs.pop(rule_id, None)
        return {"ok": True}

    def activate_finetune(
        self,
        rule_id: str,
        project_root: str,
    ) -> dict[str, Any]:
        with self._finetune_lock:
            job = dict(self._finetune_jobs.get(rule_id) or {})
        if job.get("status") != "ready":
            return {"ok": False, "error": "Finetuned build is not ready."}
        info = rules_api.get_rule(rule_id, project_root or None) or {}
        active = info.get("active") or {}
        if str(active.get("behavior_hash", "")) != str(job.get("behavior_hash", "")):
            return {
                "ok": False,
                "error": "The deployed specification changed; discard this build.",
                "stale": True,
            }
        activated = revisions.activate_artifact(
            rule_id,
            str(
                ((info.get("definition") or {}).get("source_path"))
                or job.get("source_path", "")
            ),
            str(job.get("behavior_hash", "")),
            compiler=str(job.get("compiler", "")),
            program_id=str(job.get("program_id", "")),
            compiler_snapshot=str(job.get("compiler_snapshot", "")),
            compiler_mode=revisions.EXPLICIT_COMPILER_MODE,
        )
        if not activated:
            return {
                "ok": False,
                "error": "The deployed specification changed; discard this build.",
                "stale": True,
            }
        with self._finetune_lock:
            current = self._finetune_jobs.get(rule_id)
            if current and current.get("id") == job.get("id"):
                current["status"] = "activated"
                current["finished_at"] = time.time()
        self.rules_cache.invalidate()
        return {"ok": True, "active": activated}

    def test_rule(
        self,
        rule_id: str,
        project_root: str,
        source: str | None = None,
        compiler: str | None = None,
    ) -> dict[str, Any]:
        if not self.runtime.available:
            return {"ok": False, "error": "PAW SDK not available"}
        rule = self._rule_from(rule_id, project_root, source)
        if rule is None:
            return {"ok": False, "error": "rule not found"}
        cases = list(rule.examples) or rules_api.spec_examples(rule.spec)
        if not rule.spec or not cases:
            return {
                "ok": True,
                "results": [],
                "passed": 0,
                "total": 0,
                "note": "no PAW spec Input/Output cases to test",
            }
        pid = self.runtime.program_id_for_spec(rule.spec, compiler)
        if not pid:
            return {"ok": False, "error": "compile failed"}
        self.runtime.warm(pid)
        results, passed = [], 0
        for inp, want in cases:
            want_u = str(want).strip().upper()
            got_raw = self.runtime.run(pid, str(inp))
            got = (got_raw or "").strip().upper()
            ok = bool(want_u and got) and (want_u in got or got in want_u)
            passed += 1 if ok else 0
            results.append({"want": want_u, "got": got_raw, "ok": ok})
        return {"ok": True, "results": results, "passed": passed, "total": len(cases)}

    def _validation_target(
        self,
        rule_id: str,
        project_root: str,
        rule: LoadedRule,
        requested_compiler: str = "",
        requested_program_id: str = "",
        requested_snapshot: str = "",
    ) -> dict[str, Any]:
        default_info = self.runtime.compiler_info("")
        compiler_info = (
            self.runtime.compiler_info(requested_compiler)
            if requested_compiler
            else default_info
        )
        compiler = str(requested_compiler or compiler_info.get("name", ""))
        compiler_snapshot = str(
            requested_snapshot or compiler_info.get("latest_snapshot", "")
        )
        target = {
            "compiler": compiler,
            "compiler_snapshot": compiler_snapshot,
            "program_id": "",
            "spec_hash": validation_store.spec_fingerprint(rule.spec),
            "uses_active_program": False,
        }
        cached_program = getattr(self.runtime, "cached_program_id_for_spec", None)
        if callable(cached_program) and (
            not requested_snapshot
            or requested_snapshot == str(compiler_info.get("latest_snapshot", ""))
        ):
            target["program_id"] = str(
                cached_program(rule.spec, compiler or None) or ""
            )
        if requested_program_id and requested_program_id == target["program_id"]:
            target["program_id"] = requested_program_id
        with self._finetune_lock:
            job = dict(self._finetune_jobs.get(rule_id) or {})
        if (
            job.get("status") == "ready"
            and str(job.get("compiler", "")) == compiler
            and str(job.get("spec", "")).strip() == rule.spec.strip()
            and (
                not requested_snapshot
                or str(job.get("compiler_snapshot", "")) == requested_snapshot
            )
            and (
                not requested_program_id
                or str(job.get("program_id", "")) == requested_program_id
            )
        ):
            target["program_id"] = str(job.get("program_id", ""))
            target["compiler_snapshot"] = str(
                job.get("compiler_snapshot", compiler_snapshot)
            )
        info = rules_api.get_rule(rule_id, project_root or None) or {}
        active = info.get("active") or {}
        active_program = str(active.get("program_id", ""))
        cache_path = Path(str(active.get("cache_path", "")))
        if not active_program or not cache_path.exists():
            return target
        try:
            active_source = cache_path.read_text(encoding="utf-8")
        except OSError:
            return target
        active_rule = self._rule_from(rule_id, project_root, active_source)
        if active_rule is None or active_rule.spec.strip() != rule.spec.strip():
            return target
        active_compiler = str(active.get("compiler", ""))
        if not active_compiler:
            active_compiler = str(default_info.get("name", ""))
        active_matches = bool(
            (not requested_compiler or active_compiler == compiler)
            and (
                not requested_snapshot
                or str(active.get("compiler_snapshot", "")) == requested_snapshot
            )
            and (not requested_program_id or active_program == requested_program_id)
        )
        if active_matches:
            return {
                "compiler": active_compiler,
                "compiler_snapshot": str(active.get("compiler_snapshot", "")),
                "program_id": active_program,
                "spec_hash": validation_store.spec_fingerprint(rule.spec),
                "uses_active_program": True,
            }
        artifacts = [
            dict(item)
            for item in (
                (active.get("artifacts") or {}).values()
                if isinstance(active.get("artifacts"), dict)
                else []
            )
            if isinstance(item, dict)
            and str(item.get("compiler", "")) == compiler
            and (
                not requested_snapshot
                or str(item.get("compiler_snapshot", "")) == requested_snapshot
            )
            and (
                not requested_program_id
                or str(item.get("program_id", "")) == requested_program_id
            )
            and item.get("program_id")
        ]
        artifact = max(
            artifacts,
            key=lambda item: float(item.get("created_at", 0) or 0),
            default={},
        )
        if artifact:
            target["program_id"] = str(artifact.get("program_id", ""))
            target["compiler_snapshot"] = str(
                artifact.get("compiler_snapshot", compiler_snapshot)
            )
        return target

    def run_validation_cases(
        self,
        program_id: str,
        cases: list[dict[str, Any]],
    ) -> dict[str, Any]:
        results = []
        passed = 0
        for case in rules_api.normalize_validation_cases(cases):
            actual_raw = self.runtime.run(program_id, case["input"])
            actual = (actual_raw or "").strip().upper()
            expected = case["expected"]
            valid_output = actual in ("OK", "INFO", "WARNING", "CRITICAL")
            ok = valid_output and actual == expected
            if ok:
                passed += 1
            results.append(
                {
                    **case,
                    "actual": actual_raw or "",
                    "valid_output": valid_output,
                    "ok": ok,
                }
            )
        return {
            "ok": passed == len(results),
            "passed": passed,
            "total": len(results),
            "results": results,
        }

    def _record_validation_results(
        self,
        *,
        project_root: str,
        rule_id: str,
        spec: str,
        target: dict[str, Any],
        validation: dict[str, Any],
    ) -> dict[str, Any]:
        results = self.validation_results.record(
            project_root=project_root,
            rule_id=rule_id,
            spec=spec,
            compiler=str(target.get("compiler", "")),
            compiler_snapshot=str(target.get("compiler_snapshot", "")),
            program_id=str(target.get("program_id", "")),
            results=list(validation.get("results") or []),
        )
        return {**validation, "results": results}

    def cached_validation_results(
        self,
        rule_id: str,
        project_root: str,
        source: str,
        cases: list[dict[str, Any]],
        compiler: str = "",
        compiler_snapshot: str = "",
        program_id: str = "",
    ) -> dict[str, Any]:
        rule = self._rule_from(rule_id, project_root, source)
        if rule is None or not rule.spec:
            return {"ok": False, "error": "Rule has no PAW specification."}
        normalized = rules_api.normalize_validation_cases(cases)
        target = self._validation_target(
            rule_id,
            project_root,
            rule,
            compiler,
            program_id,
            compiler_snapshot,
        )
        results = self.validation_results.matching(
            project_root=project_root,
            rule_id=rule_id,
            spec=rule.spec,
            compiler=str(target.get("compiler", "")),
            compiler_snapshot=str(target.get("compiler_snapshot", "")),
            cases=normalized,
            program_id=str(target.get("program_id", "")),
        )
        return {
            "ok": True,
            "target": target,
            "validation": {
                "passed": sum(1 for item in results if item.get("ok")),
                "matched": len(results),
                "total": len(normalized),
                "results": results,
            },
        }

    def validate_rule_cases(
        self,
        rule_id: str,
        project_root: str,
        source: str,
        cases: list[dict[str, Any]],
        compiler: str = "",
        compiler_snapshot: str = "",
        program_id: str = "",
    ) -> dict[str, Any]:
        rule = self._rule_from(rule_id, project_root, source)
        if rule is None or not rule.spec:
            return {"ok": False, "error": "Rule has no PAW specification."}
        target = self._validation_target(
            rule_id,
            project_root,
            rule,
            compiler,
            program_id,
            compiler_snapshot,
        )
        compile_started = time.time()
        program_id = str(target.get("program_id", ""))
        if not program_id:
            compiler_name = str(target.get("compiler", ""))
            compiler_info = self.runtime.compiler_info(compiler_name)
            compiled = self._compile_program_for_snapshot(
                rule.spec,
                compiler_name,
                str(target.get("compiler_snapshot", "")),
                timeout=(
                    360
                    if compiler_info.get("compiler_kind") == "finetune_lora"
                    else None
                ),
            )
            if not compiled.get("ok"):
                compile_ms = int((time.time() - compile_started) * 1000)
                _log(
                    f"validation compile failed rule={rule_id} elapsed_ms={compile_ms}"
                )
                return {
                    "ok": False,
                    "error": str(
                        compiled.get("error", "Validation compilation failed.")
                    ),
                    "compiler_catalog_stale": bool(
                        compiled.get("compiler_catalog_stale")
                    ),
                }
            program_id = str(compiled.get("program_id", ""))
            target["program_id"] = program_id
            target["compiler_snapshot"] = str(compiled.get("compiler_snapshot", ""))
        compile_ms = int((time.time() - compile_started) * 1000)
        if not program_id:
            _log(f"validation compile failed rule={rule_id} elapsed_ms={compile_ms}")
            return {"ok": False, "error": "Validation compilation failed."}
        run_started = time.time()
        validation = self.run_validation_cases(program_id, cases)
        validation = self._record_validation_results(
            project_root=project_root,
            rule_id=rule_id,
            spec=rule.spec,
            target=target,
            validation=validation,
        )
        run_ms = int((time.time() - run_started) * 1000)
        _log(
            f"validation complete rule={rule_id} compile_ms={compile_ms} "
            f"run_ms={run_ms} cases={len(cases)}"
        )
        return {
            "ok": True,
            "validation": validation,
            "target": target,
            "timing": {
                "compile_ms": compile_ms,
                "run_ms": run_ms,
            },
        }

    def _project_catalog(self) -> list[dict[str, str]]:
        discovered = codex_projects.discover_projects(limit=100)
        by_path = {
            str(item["path"]): {
                "path": str(item["path"]),
                "name": str(item.get("name") or Path(item["path"]).name),
            }
            for item in discovered
            if item.get("path")
        }
        with self._state_lock:
            known = list(self.known_projects)
        for path in known:
            by_path.setdefault(path, {"path": path, "name": Path(path).name})
        return sorted(by_path.values(), key=lambda item: item["name"].lower())

    def deployment_plan(self, rule_id: str, project_root: str = "") -> dict[str, Any]:
        projects = self._project_catalog()
        if project_root and all(item["path"] != project_root for item in projects):
            projects.append(
                {
                    "path": project_root,
                    "name": Path(project_root).name,
                }
            )
            projects.sort(key=lambda item: item["name"].lower())
        roots = [item["path"] for item in projects]
        info = rules_api.get_rule(rule_id, project_root or None)
        if info and info.get("scope") == "builtin":
            info = None
        coverage = (
            rules_api.rule_coverage(rule_id, roots)
            if info
            else {
                "mode": "selected",
                "all_projects": False,
                "selected_projects": [project_root] if project_root else [],
            }
        )
        draft_coverage = rules_api.deployment_coverage_draft(rule_id)
        source_path = str(((info or {}).get("definition") or {}).get("source_path", ""))
        consumers = []
        overrides = []
        for root in roots:
            effective = rules_api.get_rule(rule_id, root)
            effective_path = str(
                ((effective or {}).get("definition") or {}).get("source_path", "")
            )
            if effective and effective.get("scope") == "project":
                overrides.append(root)
            if (
                source_path
                and effective_path == source_path
                and rules_api.is_enabled(rule_id, root)
            ):
                consumers.append(root)
        return {
            "ok": True,
            "rule_id": rule_id,
            "definition": (info or {}).get("definition"),
            "source_scope": (info or {}).get("scope", ""),
            "working_hash": (info or {}).get("working_hash", ""),
            "active_hash": (info or {}).get("active_hash", ""),
            "coverage": coverage,
            "draft_coverage": draft_coverage,
            "projects": projects,
            "consumers": consumers,
            "project_overrides": overrides,
            "impact_count": len(consumers),
        }

    def prepare_rule_deployment(self, req: dict[str, Any]) -> dict[str, Any]:
        rule_id = str(req.get("rule_id", ""))
        source = str(req.get("source", ""))
        project_root = str(req.get("project_root", ""))
        valid, error = rules_api.validate_editor_source(source)
        if not valid:
            return {"ok": False, "error": error}
        projection = rules_api.source_projection(source)
        if projection.get("id") != rule_id:
            return {"ok": False, "error": "source ID does not match the rule"}
        current = rules_api.get_rule(rule_id, project_root or None)
        if current and current.get("scope") == "builtin":
            current = None
        current_active = (current or {}).get("active") or {}
        coverage_roots = [item["path"] for item in self._project_catalog()]
        expected_coverage = (
            rules_api.rule_coverage(rule_id, coverage_roots)
            if current
            else {
                "mode": "selected",
                "all_projects": False,
                "selected_projects": [],
            }
        )
        expected_active_hash = str(
            req.get("expected_active_hash", "")
            if "expected_active_hash" in req
            else current_active.get("source_hash", "")
        )
        source_changed = bool(req.get("source_changed", True))
        source_behavior_hash = revisions.behavior_hash(source)
        active_behavior_hash = str(current_active.get("behavior_hash", ""))
        behavior_changed = bool(
            current_active and active_behavior_hash != source_behavior_hash
        )
        default_compiler = self.runtime.compiler_info("")
        active_compiler = str(
            current_active.get("compiler") or default_compiler.get("name", "")
        )
        active_compiler_mode = str(
            current_active.get("compiler_mode") or revisions.AUTOMATIC_COMPILER_MODE
        )
        requested_compiler = str(req.get("compiler", ""))
        compiler_mode = str(
            req.get("compiler_mode")
            or (revisions.EXPLICIT_COMPILER_MODE if requested_compiler else "")
            or active_compiler_mode
        )
        if compiler_mode not in revisions.COMPILER_MODES:
            return {"ok": False, "error": "invalid compiler mode"}
        compiler = str(requested_compiler or active_compiler)
        if compiler_mode == revisions.AUTOMATIC_COMPILER_MODE:
            if current_active and not behavior_changed:
                compiler = active_compiler
            else:
                automatic = self._automatic_base_compiler()
                compiler = str(automatic.get("name", "")) or compiler
        compiler_info = self.runtime.compiler_info(compiler)
        compiler_snapshot = str(
            (
                current_active.get("compiler_snapshot", "")
                if (
                    compiler_mode == revisions.AUTOMATIC_COMPILER_MODE
                    and current_active
                    and not behavior_changed
                )
                else req.get("compiler_snapshot")
            )
            or compiler_info.get("latest_snapshot", "")
        )
        compiler_changed = bool(
            current_active
            and (
                compiler != active_compiler
                or (
                    compiler_snapshot
                    and str(current_active.get("compiler_snapshot", ""))
                    != compiler_snapshot
                )
            )
        )
        compiler_mode_changed = bool(
            current_active and compiler_mode != active_compiler_mode
        )
        validation_cases = rules_api.normalize_validation_cases(
            req.get("validation_cases")
            if "validation_cases" in req
            else rules_api.validation_cases(rule_id, project_root or None)
        )
        validation = {"ok": True, "passed": 0, "total": 0, "results": []}
        tested = {"ok": True, "results": [], "passed": 0, "total": 0}
        rule = self._rule_from(rule_id, project_root, source)
        if rule is None:
            return {"ok": False, "error": "rule could not be loaded"}
        program_id = (
            str(current_active.get("program_id", ""))
            if not behavior_changed and not compiler_changed
            else ""
        )
        requested_program = str(req.get("program_id", ""))
        if requested_program:
            with self._finetune_lock:
                job = dict(self._finetune_jobs.get(rule_id) or {})
            candidate_valid = bool(
                job.get("status") == "ready"
                and str(job.get("behavior_hash", "")) == source_behavior_hash
                and str(job.get("compiler", "")) == compiler
                and str(job.get("program_id", "")) == requested_program
                and (
                    not compiler_snapshot
                    or str(job.get("compiler_snapshot", "")) == compiler_snapshot
                )
            )
            active_valid = bool(
                not behavior_changed
                and not compiler_changed
                and str(current_active.get("program_id", "")) == requested_program
            )
            cached_program = getattr(self.runtime, "cached_program_id_for_spec", None)
            cached_valid = bool(
                callable(cached_program)
                and (
                    not compiler_snapshot
                    or str(compiler_info.get("latest_snapshot", ""))
                    == compiler_snapshot
                )
                and str(cached_program(rule.spec, compiler or None))
                == requested_program
            )
            artifact = next(
                (
                    dict(item)
                    for item in (
                        (current_active.get("artifacts") or {}).values()
                        if isinstance(current_active.get("artifacts"), dict)
                        else []
                    )
                    if isinstance(item, dict)
                    and str(item.get("behavior_hash", "")) == source_behavior_hash
                    and str(item.get("compiler", "")) == compiler
                    and str(item.get("program_id", "")) == requested_program
                    and (
                        not compiler_snapshot
                        or str(item.get("compiler_snapshot", "")) == compiler_snapshot
                    )
                ),
                {},
            )
            artifact_valid = bool(artifact)
            if candidate_valid or active_valid or cached_valid or artifact_valid:
                program_id = requested_program
                if candidate_valid:
                    compiler_snapshot = str(
                        job.get("compiler_snapshot", compiler_snapshot)
                    )
                elif artifact_valid:
                    compiler_snapshot = str(
                        artifact.get("compiler_snapshot", compiler_snapshot)
                    )
        needs_program = bool(
            rule.spec
            and (
                behavior_changed
                or compiler_changed
                or not program_id
                or not current_active
            )
        )
        if needs_program:
            if (
                str(compiler_info.get("compiler_kind", "")) == "finetune_lora"
                and not program_id
            ):
                return {
                    "ok": False,
                    "error": (
                        f"Build {compiler_info.get('description') or compiler} "
                        "for the current draft before deploying."
                    ),
                    "compiler_build_required": True,
                }
            if rule.spec and not program_id:
                compiled = self.compile_rule(
                    rule_id,
                    project_root,
                    source=source,
                    compiler=compiler or None,
                    expected_snapshot=compiler_snapshot,
                )
                if not compiled.get("ok"):
                    return compiled
                program_id = str(compiled.get("program_id", ""))
                compiler = str(compiled.get("compiler", compiler))
                compiler_snapshot = str(
                    compiled.get("compiler_snapshot")
                    or (compiled.get("compiler_info") or {}).get("latest_snapshot", "")
                )
        token = secrets.token_urlsafe(24)
        prepared = {
            "token": token,
            "rule_id": rule_id,
            "source": source,
            "source_hash": revisions.hash_source(source),
            "project_root": project_root,
            "definition": (current or {}).get("definition"),
            "source_scope": (current or {}).get("scope", ""),
            "expected_active_hash": expected_active_hash,
            "expected_coverage": expected_coverage,
            "compiler": compiler,
            "compiler_mode": compiler_mode,
            "program_id": program_id,
            "compiler_snapshot": compiler_snapshot,
            "coverage": dict(req.get("coverage") or {}),
            "warnings": [str(item) for item in (req.get("warnings") or [])],
            "source_changed": source_changed,
            "behavior_changed": behavior_changed,
            "compiler_changed": compiler_changed,
            "compiler_mode_changed": compiler_mode_changed,
            "created_at": time.time(),
            "test": tested,
            "validation_cases": validation_cases,
            "validation_cases_from_working_copy": bool(
                req.get("validation_cases_from_working_copy")
            ),
            "validation": validation,
        }
        with self._state_lock:
            self._prepared_deployments[token] = prepared
        return {
            "ok": True,
            "token": token,
            "source_hash": prepared["source_hash"],
            "test": tested,
            "program_id": program_id,
            "compiler": compiler,
            "compiler_mode": compiler_mode,
            "validation": validation,
        }

    def commit_rule_deployment(self, token: str) -> dict[str, Any]:
        with self._deployment_lock:
            with rules_api.rule_mutation_transaction():
                return self._commit_rule_deployment(token)

    def _commit_rule_deployment(self, token: str) -> dict[str, Any]:
        with self._state_lock:
            prepared = self._prepared_deployments.pop(token, None)
        if not prepared:
            return {"ok": False, "error": "deployment expired; prepare again"}
        if time.time() - float(prepared.get("created_at", 0)) > 900:
            return {"ok": False, "error": "deployment expired; prepare again"}
        rule_id = prepared["rule_id"]
        project_root = prepared.get("project_root", "")
        current = rules_api.get_rule(rule_id, project_root or None)
        if current and current.get("scope") == "builtin":
            current = None
        prepared_definition = prepared.get("definition") or {}
        current_definition = (current or {}).get("definition") or {}
        if prepared_definition:
            if str(current_definition.get("source_path", "")) != str(
                prepared_definition.get("source_path", "")
            ) or str(current_definition.get("source_hash", "")) != str(
                prepared_definition.get("source_hash", "")
            ):
                return {
                    "ok": False,
                    "error": "the working draft changed; prepare again",
                }
        elif current:
            return {
                "ok": False,
                "error": "a rule with this ID appeared; prepare again",
            }
        current_active = (current or {}).get("active") or {}
        if str(current_active.get("source_hash", "")) != str(
            prepared.get("expected_active_hash", "")
        ):
            return {
                "ok": False,
                "error": "the deployed revision changed; prepare again",
            }
        migrated_to_library = bool(current and current.get("scope") == "project")
        if (
            migrated_to_library
            and (config.global_rules_dir() / rule_id / "rule.py").exists()
        ):
            return {
                "ok": False,
                "error": "My Rule Library already contains this rule ID",
                "conflict": True,
            }
        expected_hash = (
            ""
            if migrated_to_library
            else str(prepared_definition.get("source_hash", ""))
        )
        projects = self._project_catalog()
        roots = [item["path"] for item in projects]
        old_coverage = rules_api.rule_coverage(rule_id, roots)
        expected_coverage = prepared.get("expected_coverage") or {}
        if prepared_definition and (
            str(old_coverage.get("mode")) != str(expected_coverage.get("mode"))
            or sorted(old_coverage.get("selected_projects") or [])
            != sorted(expected_coverage.get("selected_projects") or [])
        ):
            return {
                "ok": False,
                "error": "project coverage changed; prepare again",
                "expected_coverage": expected_coverage,
                "current_coverage": old_coverage,
            }
        saved = rules_api.save_library_draft(
            rule_id,
            prepared["source"],
            expected_source_hash=expected_hash,
            expected_absent=not bool(current) or migrated_to_library,
        )
        if not saved.get("ok"):
            return saved
        path = saved["path"]
        current_source_path = str(current_definition.get("source_path", ""))
        latest_validation_cases = (
            rules_api.validation_cases_for_path(current_source_path)
            if (
                current_source_path
                and prepared.get("validation_cases_from_working_copy")
            )
            else prepared.get("validation_cases") or []
        )
        validation_saved = rules_api.save_validation_cases(
            path, latest_validation_cases
        )
        if not validation_saved.get("ok"):
            return validation_saved
        previous_active = revisions.active_info(rule_id, path)
        active = (
            revisions.activate(
                rule_id,
                path,
                saved["source"],
                compiler=prepared.get("compiler") or None,
                program_id=prepared.get("program_id") or None,
                warnings=prepared.get("warnings") or [],
                compiler_snapshot=prepared.get("compiler_snapshot") or None,
                compiler_mode=prepared.get("compiler_mode"),
            )
            if (
                prepared.get("source_changed")
                or prepared.get("compiler_changed")
                or prepared.get("compiler_mode_changed")
                or not previous_active
            )
            else previous_active
        )
        coverage_request = prepared.get("coverage") or {}
        coverage = rules_api.set_rule_coverage(
            rule_id,
            str(coverage_request.get("mode", "selected")),
            list(coverage_request.get("selected_projects") or []),
            roots,
            name=str(saved.get("name", "")),
        )
        if not coverage.get("ok"):
            revisions.restore_active(rule_id, path, previous_active)
            if not current or migrated_to_library:
                definition = saved.get("definition") or {}
                rules_api.delete_rule_definition(
                    rule_id,
                    "global",
                    None,
                    str(definition.get("source_path", "")),
                    str(definition.get("source_hash", "")),
                    project_roots=roots,
                )
            if migrated_to_library:
                restored = rules_api.set_rule_coverage(
                    rule_id,
                    str(old_coverage.get("mode", "selected")),
                    list(old_coverage.get("selected_projects") or []),
                    roots,
                    name=str(saved.get("name", "")),
                )
                if not restored.get("ok"):
                    all_projects = old_coverage.get("mode") == "all"
                    rules_api.set_enabled(rule_id, all_projects, None)
                    selected_before = set(old_coverage.get("selected_projects") or [])
                    for root in roots:
                        rules_api.set_enabled(
                            rule_id,
                            all_projects or root in selected_before,
                            root,
                            name=str(saved.get("name", "")),
                        )
            self.rules_cache.invalidate()
            return coverage
        if migrated_to_library:
            definition = current_definition
            removed = rules_api.delete_rule_definition(
                rule_id,
                "project",
                str(definition.get("project_root") or project_root),
                str(definition.get("source_path", "")),
                str(definition.get("source_hash", "")),
                project_roots=roots,
            )
            if not removed.get("ok"):
                restored = rules_api.set_rule_coverage(
                    rule_id,
                    str(old_coverage.get("mode", "selected")),
                    list(old_coverage.get("selected_projects") or []),
                    roots,
                    name=str(saved.get("name", "")),
                )
                if not restored.get("ok"):
                    all_projects = old_coverage.get("mode") == "all"
                    rules_api.set_enabled(rule_id, all_projects, None)
                    selected_before = set(old_coverage.get("selected_projects") or [])
                    for root in roots:
                        rules_api.set_enabled(
                            rule_id,
                            all_projects or root in selected_before,
                            root,
                            name=str(saved.get("name", "")),
                        )
                revisions.restore_active(rule_id, path, previous_active)
                global_definition = saved.get("definition") or {}
                rules_api.delete_rule_definition(
                    rule_id,
                    "global",
                    None,
                    str(global_definition.get("source_path", "")),
                    str(global_definition.get("source_hash", "")),
                    project_roots=roots,
                )
                self.rules_cache.invalidate()
                return removed
        rules_api.clear_deployment_coverage_draft(rule_id)
        self.rules_cache.invalidate()
        desired = (
            roots
            if coverage.get("mode") == "all"
            else list(coverage.get("selected_projects") or [])
        )
        affected = []
        canonical_path = str(Path(path).resolve())
        for root in desired:
            effective = rules_api.get_rule(rule_id, root)
            effective_path = str(
                ((effective or {}).get("definition") or {}).get("source_path", "")
            )
            if effective_path and str(Path(effective_path).resolve()) == canonical_path:
                affected.append(root)
        for root in affected:
            with self._state_lock:
                self._warmed.add(root)
            self.work.submit(self._warm, root)
        compiler_build_discarded = self._discard_stale_finetune_job(
            rule_id, str(active.get("behavior_hash", ""))
        )
        optimization = self._queue_automatic_optimization(
            rule_id=rule_id,
            project_root=project_root,
            source_path=path,
            source=saved["source"],
            active=active,
        )
        return {
            "ok": True,
            "rule": rules_api.get_rule(rule_id, None),
            "active": active,
            "coverage": coverage,
            "affected_projects": affected,
            "impact_count": len(affected),
            "migrated_to_library": migrated_to_library,
            "warnings": list(prepared.get("warnings") or []),
            "validation": prepared.get("validation") or {},
            "compiler_build_discarded": compiler_build_discarded,
            "optimization": optimization,
        }

    # --- request dispatch ------------------------------------------------
    def dispatch(self, req: dict[str, Any]) -> dict[str, Any]:
        rtype = req.get("type")
        if rtype == "ping":
            return {
                "ok": True,
                "pid": os.getpid(),
                "paw": self.runtime.available,
                "protocol": PROTOCOL_VERSION,
                "version": __version__,
                "started_at": self.started_at,
            }
        if rtype == "snapshot":
            return self.snapshot()
        if rtype == "event":
            ev = req.get("event")
            if isinstance(ev, dict):
                accepted = self.handle_event(ev)
                return {"ok": True, "accepted": accepted}
            return {"ok": True, "accepted": False}
        if rtype == "warm":
            proj = req.get("project_root", "")
            if proj:
                with self._state_lock:
                    self.known_projects.add(proj)
            self.work.submit(self._warm, proj)
            return {"ok": True}
        if rtype == "retry_health_issue":
            project_root = str(req.get("project_root", ""))
            roots = list(req.get("affected_projects") or [])
            if project_root and project_root not in roots:
                roots.append(project_root)
            for root in roots:
                self.work.submit(self._warm, str(root))
            return {"ok": True}
        if rtype == "verdicts":
            return {
                "ok": True,
                "verdicts": self.store.recent(
                    limit=int(req.get("limit", 100)),
                    project_root=req.get("project_root"),
                    include_acknowledged=bool(req.get("include_acknowledged")),
                    include_suppressed=bool(req.get("include_suppressed")),
                ),
            }
        if rtype == "finding_groups":
            if req.get("reviewed_only"):
                groups = self.store.history_grouped(
                    project_root=req.get("project_root"),
                    limit=int(req.get("limit", 1000)),
                )
            else:
                groups = self.store.grouped(
                    project_root=req.get("project_root"),
                    include_reviewed=bool(req.get("include_reviewed")),
                    include_suppressed=bool(req.get("include_suppressed")),
                    limit=int(req.get("limit", 1000)),
                )
            summaries_by_project: dict[str, dict[str, dict[str, Any]]] = {}
            for group in groups:
                project_root = str(group.get("project_root", ""))
                if project_root not in summaries_by_project:
                    summaries_by_project[project_root] = {
                        rule["id"]: rule for rule in rules_api.list_rules(project_root)
                    }
                self._decorate_finding_group(
                    group,
                    summaries_by_project[project_root].get(
                        str(group.get("rule_id", "")), {}
                    ),
                )
            return {"ok": True, "groups": groups}
        if rtype == "finding_occurrences":
            fingerprint = str(req.get("fingerprint", ""))
            rows = self.store.occurrences(
                fingerprint,
                limit=max(1, min(500, int(req.get("limit", 100)))),
                include_reviewed=bool(req.get("include_reviewed")),
            )
            summaries_by_project: dict[str, dict[str, dict[str, Any]]] = {}
            for row in rows:
                project_root = str(row.get("project_root", ""))
                if project_root not in summaries_by_project:
                    summaries_by_project[project_root] = {
                        rule["id"]: rule for rule in rules_api.list_rules(project_root)
                    }
                self._decorate_finding_group(
                    row,
                    summaries_by_project[project_root].get(
                        str(row.get("rule_id", "")), {}
                    ),
                )
            return {"ok": True, "occurrences": rows}
        if rtype == "finding_detail":
            finding_id = int(req.get("id", 0))
            finding = self.store.get(finding_id)
            if not finding:
                return {"ok": False, "error": "finding not found"}
            entry = audit.read_finding(
                finding["project_root"],
                finding_id,
            )
            current_rule = (
                rules_api.get_rule(finding["rule_id"], finding["project_root"]) or {}
            )
            current_source = str(current_rule.get("source", ""))
            evaluation = dict(finding.get("evaluation") or {})
            if evaluation.get("schema_version") != 4:
                return {"ok": False, "error": "unsupported finding schema"}
            recorded_source = str((evaluation.get("rule") or {}).get("source", ""))
            working_hash = (
                hashlib.sha256(current_source.encode("utf-8")).hexdigest()
                if current_source
                else ""
            )
            current_hash = current_rule.get("active_hash") or working_hash
            current_behavior_hash = str(
                current_rule.get("active_behavior_hash")
                or current_rule.get("working_behavior_hash")
                or (revisions.behavior_hash(current_source) if current_source else "")
            )
            recorded_behavior_hash = str(
                finding.get("behavior_hash")
                or (evaluation.get("rule") or {}).get("behavior_hash")
                or (revisions.behavior_hash(recorded_source) if recorded_source else "")
            )
            recorded_rule_title = str(finding.get("rule_title", ""))
            current_rule_title = str(
                current_rule.get("name")
                or current_rule.get("title")
                or recorded_rule_title
            )
            finding["recorded_rule_title"] = recorded_rule_title
            finding["rule_title"] = current_rule_title
            ledger = self.ledgers.get(
                finding.get("conversation_id", ""), finding["project_root"]
            )
            ledger_window = ledger.context_window(
                finding.get("trigger_event_id", ""),
                center_ts=finding.get("ts"),
                before=30,
                after=30,
                through_seq=evaluation.get("context_through_seq"),
            )
            return {
                "ok": True,
                "finding": finding,
                "trace": (entry or {}).get("trace", []),
                "audit": entry,
                "evaluation": evaluation,
                "ledger": ledger_window,
                "current_rule": current_rule,
                "current_rule_projection": rules_api.source_projection(current_source)
                if current_source
                else {},
                "recorded_rule_projection": rules_api.source_projection(recorded_source)
                if recorded_source
                else {},
                "current_rule_hash": current_hash,
                "current_behavior_hash": current_behavior_hash,
                "recorded_behavior_hash": recorded_behavior_hash,
                "working_rule_hash": working_hash,
                "rule_changed": bool(
                    recorded_behavior_hash
                    and current_behavior_hash
                    and recorded_behavior_hash != current_behavior_hash
                ),
            }
        if rtype == "evaluation_history":
            project_root = str(req.get("project_root", ""))
            roots = (
                [project_root]
                if project_root
                else [item["path"] for item in self._project_catalog()]
            )
            rows = []
            for root in roots:
                root_rows = evaluation_log.history(
                    root,
                    rule_id=str(req.get("rule_id", "")),
                    limit=int(req.get("limit", 500)),
                )
                expected_by_input = {
                    str(case.get("input", "")): str(case.get("expected", ""))
                    for case in rules_api.validation_cases(
                        str(req.get("rule_id", "")), root
                    )
                }
                for row in root_rows:
                    input_text = str((row.get("input") or {}).get("text", ""))
                    row["expected"] = expected_by_input.get(input_text, "")
                rows.extend(root_rows)
            rows.sort(key=lambda item: float(item.get("timestamp", 0)), reverse=True)
            return {
                "ok": True,
                "evaluations": rows[: max(1, min(5000, int(req.get("limit", 500))))],
                "log_paths": [
                    str(config.project_evaluation_log_file(root)) for root in roots
                ],
            }
        if rtype == "evaluation_detail":
            project_root = str(req.get("project_root", ""))
            value = evaluation_log.get(project_root, str(req.get("evaluation_id", "")))
            return {
                "ok": bool(value),
                "evaluation": value,
                **({} if value else {"error": "evaluation not found"}),
            }
        if rtype == "add_validation_case":
            return rules_api.add_validation_case(
                str(req.get("rule_id", "")),
                str(req.get("project_root", "")) or None,
                str(req.get("input", "")),
                str(req.get("expected", "")),
            )
        if rtype == "save_validation_cases":
            with rules_api.rule_mutation_transaction():
                info = rules_api.get_rule(
                    str(req.get("rule_id", "")),
                    str(req.get("project_root", "")) or None,
                )
                source_path = str(
                    ((info or {}).get("definition") or {}).get("source_path", "")
                )
                return rules_api.save_validation_cases(
                    source_path, list(req.get("validation_cases") or [])
                )
        if rtype == "ledger_window":
            finding = self.store.get(int(req.get("id", 0)))
            if not finding:
                return {"ok": False, "error": "finding not found"}
            ledger = self.ledgers.get(
                finding.get("conversation_id", ""), finding["project_root"]
            )
            evaluation = dict(finding.get("evaluation") or {})
            if evaluation.get("schema_version") != 4:
                return {"ok": False, "error": "unsupported finding schema"}
            start_value = req.get("start")
            return {
                "ok": True,
                "ledger": ledger.context_window(
                    finding.get("trigger_event_id", ""),
                    center_ts=finding.get("ts"),
                    start=(int(start_value) if start_value is not None else None),
                    limit=max(1, min(100, int(req.get("limit", 60)))),
                    through_seq=evaluation.get("context_through_seq"),
                ),
            }
        if rtype == "by_project":
            return {"ok": True, "projects": self.store.by_project()}
        if rtype in ("acknowledge", "review"):
            n = self.store.acknowledge(
                ids=req.get("ids"),
                project_root=req.get("project_root"),
                fingerprint=req.get("fingerprint"),
                reason=req.get("reason"),
            )
            return {"ok": True, "acknowledged": n}
        if rtype == "reopen":
            n = self.store.reopen(
                ids=req.get("ids"), fingerprint=req.get("fingerprint")
            )
            return {"ok": True, "reopened": n}
        if rtype == "dismiss_attention":
            n = self.attention.clear(
                attention_id=int(req.get("id", 0)),
                reason="not waiting",
            )
            return {"ok": True, "cleared": n}
        if rtype == "known_projects":
            with self._state_lock:
                known = sorted(self.known_projects)
            return {"ok": True, "known_projects": known}
        if rtype == "rule_library":
            discovered = [
                item["path"] for item in codex_projects.discover_projects(limit=100)
            ]
            with self._state_lock:
                known = list(self.known_projects)
            project_paths = list(dict.fromkeys([*known, *discovered]))
            rules, errors = rules_api.list_rule_library_with_errors(project_paths)
            builtin_ids = set(scaffold.builtin_ids())
            for rule in rules:
                if rule.get("source_origin") == "project":
                    root = rule.get("project_root", "")
                    rule["usage_count"] = (
                        1 if root and rules_api.is_enabled(rule["id"], root) else 0
                    )
                else:
                    rule["usage_count"] = sum(
                        1
                        for root in project_paths
                        if rules_api.is_enabled(rule["id"], root)
                    )
            for error in errors:
                error["is_builtin"] = error.get("id") in builtin_ids
                if error.get("scope") == "project":
                    root = error.get("project_root", "")
                    error["usage_count"] = (
                        1 if root and rules_api.is_enabled(error["id"], root) else 0
                    )
                else:
                    error["usage_count"] = sum(
                        1
                        for root in project_paths
                        if rules_api.is_enabled(error["id"], root)
                    )
            return {
                "ok": True,
                "rules": rules,
                "errors": errors,
                "builtins": scaffold.builtin_ids(),
            }
        if rtype == "rules":
            project_root = req.get("project_root", "")
            errors = self.rules_cache.errors(project_root)
            rules = rules_api.list_rules(project_root or None)
            project_paths = [
                item["path"] for item in codex_projects.discover_projects(limit=100)
            ]
            with self._state_lock:
                warm = {
                    rid: dict(value)
                    for rid, value in self._warm_state.get(project_root, {}).items()
                }
            builtin_ids = set(scaffold.builtin_ids())
            for rule in rules:
                rule["is_builtin"] = rule["id"] in builtin_ids
                state = warm.get(rule["id"], {})
                rule["warm_status"] = state.get(
                    "status", "disabled" if not rule.get("enabled") else "idle"
                )
                rule["warm_error"] = state.get("error", "")
                if rule.get("source_origin") == "project":
                    rule["usage_count"] = (
                        1 if rules_api.is_enabled(rule["id"], project_root) else 0
                    )
                else:
                    rule["usage_count"] = sum(
                        1
                        for path in project_paths
                        if rules_api.is_enabled(rule["id"], path)
                    )
            error_rows = []
            for error in errors:
                summary = rules_api.summarize_rule_error(
                    error.path,
                    error.scope,
                    error.error,
                    project_root if error.scope == "project" else None,
                )
                summary["is_builtin"] = summary["id"] in builtin_ids
                summary["usage_count"] = (
                    1
                    if summary.get("scope") == "project"
                    and rules_api.is_enabled(summary["id"], project_root)
                    else sum(
                        1
                        for path in project_paths
                        if rules_api.is_enabled(summary["id"], path)
                    )
                    if summary.get("scope") == "global"
                    else 0
                )
                error_rows.append(summary)
            return {
                "ok": True,
                "rules": rules,
                "errors": error_rows,
                "builtins": scaffold.builtin_ids(),
            }
        if rtype == "rule_get":
            project_root = req.get("project_root") or ""
            info = rules_api.get_rule(req["rule_id"], project_root or None)
            if info:
                queued = (
                    self.deployment_queue.active_for_rule(info["id"])
                    or self.deployment_queue.latest_for_rule(info["id"])
                    or {}
                )
                queue_overlay = bool(
                    queued.get("status")
                    in (
                        "waiting_for_build",
                        "building",
                        "checking",
                        "validating",
                        "deploying",
                        "failed",
                    )
                    and queued.get("source")
                    and str((info.get("definition") or {}).get("source_hash", ""))
                    == str(queued.get("expected_definition_hash", ""))
                )
                if queue_overlay:
                    info["source"] = str(queued["source"])
                    info["working_hash"] = str(queued.get("source_hash", ""))
                    info["draft_changes"] = str(queued.get("source_hash", "")) != str(
                        (info.get("active") or {}).get("source_hash", "")
                    )
                    info["validation_cases"] = list(
                        queued.get("validation_cases") or []
                    )
                info["projection"] = rules_api.source_projection(info.get("source", ""))
                info["is_builtin"] = info["id"] in set(scaffold.builtin_ids())
                info["deployment"] = self.deployment_plan(info["id"], project_root)
                if queue_overlay:
                    info["deployment"]["draft_coverage"] = {
                        **dict(queued.get("coverage") or {}),
                        "compiler": str(queued.get("compiler", "")),
                        "compiler_snapshot": str(queued.get("compiler_snapshot", "")),
                        "confirmed": True,
                    }
            return {
                "ok": bool(info),
                "rule": info,
                **({} if info else {"error": "rule not found"}),
            }
        if rtype == "deployment_plan":
            return self.deployment_plan(req["rule_id"], req.get("project_root", ""))
        if rtype == "prepare_deployment":
            return self.prepare_rule_deployment(req)
        if rtype == "commit_deployment":
            return self.commit_rule_deployment(str(req.get("token", "")))
        if rtype == "queue_deployment":
            return self.queue_deployment(req)
        if rtype == "deployment_queue_status":
            return self.deployment_queue_status(
                str(req.get("rule_id", "")),
                str(req.get("deployment_id", "")),
            )
        if rtype == "cancel_queued_deployment":
            return self.cancel_queued_deployment(
                str(req.get("rule_id", "")),
                str(req.get("reason", "Cancelled by user.")),
                str(req.get("deployment_id", "")),
            )
        if rtype == "queue_validation":
            return self.queue_validation(req)
        if rtype == "validation_queue_status":
            return self.validation_queue_status(
                str(req.get("rule_id", "")),
                str(req.get("validation_id", "")),
            )
        if rtype == "cancel_queued_validation":
            return self.cancel_queued_validation(
                str(req.get("rule_id", "")),
                str(req.get("reason", "Cancelled by user.")),
                str(req.get("validation_id", "")),
            )
        if rtype == "finetune_status":
            return self.finetune_status(
                str(req.get("rule_id", "")),
                str(req.get("project_root", "")),
            )
        if rtype == "compiler_catalog":
            return {
                "ok": True,
                **self.runtime.list_compilers(refresh=bool(req.get("refresh"))),
            }
        if rtype == "start_finetune":
            return self.start_finetune(
                str(req.get("rule_id", "")),
                str(req.get("project_root", "")),
                str(req.get("compiler", "")),
                str(req.get("source", "")),
                list(req.get("validation_cases") or []),
            )
        if rtype == "cancel_finetune":
            return self.cancel_finetune(str(req.get("rule_id", "")))
        if rtype == "discard_finetune":
            return self.discard_finetune(str(req.get("rule_id", "")))
        if rtype == "activate_finetune":
            return self.activate_finetune(
                str(req.get("rule_id", "")),
                str(req.get("project_root", "")),
            )
        if rtype == "validate_rule":
            if req.get("strict"):
                valid, error = rules_api.validate_editor_source(req.get("source", ""))
            else:
                valid, error = rules_api.check_source_syntax(req.get("source", ""))
            return {"ok": valid, "error": error}
        if rtype == "cached_validation_results":
            return self.cached_validation_results(
                str(req.get("rule_id", "")),
                str(req.get("project_root", "")),
                str(req.get("source", "")),
                list(req.get("validation_cases") or []),
                str(req.get("compiler", "")),
                str(req.get("compiler_snapshot", "")),
                str(req.get("program_id", "")),
            )
        if rtype == "validate_rule_cases":
            return self.validate_rule_cases(
                str(req.get("rule_id", "")),
                str(req.get("project_root", "")),
                str(req.get("source", "")),
                list(req.get("validation_cases") or []),
                str(req.get("compiler", "")),
                str(req.get("compiler_snapshot", "")),
                str(req.get("program_id", "")),
            )
        if rtype == "new_rule_draft":
            project_root = req.get("project_root", "")
            existing = {rule["id"] for rule in rules_api.list_rules(None)}
            rule_id = new_rule_id()
            while (
                rule_id in existing
                or (config.global_rules_dir() / rule_id / "rule.py").exists()
            ):
                rule_id = new_rule_id()
            template = req.get("template", "paw")
            source = (
                rules_api.draft_plain_rule_source(rule_id)
                if template == "python"
                else rules_api.draft_rule_source(rule_id)
            )
            coverage_mode = str(
                req.get(
                    "coverage_mode",
                    "selected" if project_root else "all",
                )
            )
            if coverage_mode not in ("all", "selected"):
                coverage_mode = "all" if not project_root else "selected"
            initial_coverage = {
                "mode": coverage_mode,
                "all_projects": coverage_mode == "all",
                "selected_projects": (
                    [project_root]
                    if coverage_mode == "selected" and project_root
                    else []
                ),
                "confirmed": True,
            }
            deployment = self.deployment_plan(rule_id, project_root)
            deployment["coverage"] = dict(initial_coverage)
            deployment["draft_coverage"] = dict(initial_coverage)
            return {
                "ok": True,
                "rule": {
                    "id": rule_id,
                    "title": (
                        "Flag a deterministic text pattern."
                        if template == "python"
                        else "Use Git for source synchronization."
                    ),
                    "scope": "global",
                    "project_root": project_root,
                    "source": source,
                    "projection": rules_api.source_projection(source),
                    "path": "",
                    "enabled": False,
                    "muted": False,
                    "new_draft": True,
                    "deployment": deployment,
                },
            }
        if rtype == "save_library_draft":
            valid, error = rules_api.validate_editor_source(req.get("source", ""))
            if not valid:
                return {"ok": False, "error": error}
            result = rules_api.save_library_draft(
                req["rule_id"],
                req.get("source", ""),
                expected_source_hash=req.get("expected_source_hash", ""),
                expected_absent=bool(req.get("expected_absent")),
            )
            if result.get("ok"):
                validation_saved = rules_api.save_validation_cases(
                    result.get("path", ""), list(req.get("validation_cases") or [])
                )
                if not validation_saved.get("ok"):
                    return validation_saved
                result["validation_cases"] = validation_saved["cases"]
                if req.get("coverage"):
                    coverage_saved = rules_api.save_deployment_coverage_draft(
                        result["id"], dict(req["coverage"])
                    )
                    if not coverage_saved.get("ok"):
                        return coverage_saved
                self.rules_cache.invalidate()
            return result
        if rtype == "save_project_draft":
            valid, error = rules_api.validate_editor_source(req.get("source", ""))
            if not valid:
                return {"ok": False, "error": error}
            result = rules_api.save_project_draft(
                req["rule_id"],
                req.get("source", ""),
                req["project_root"],
                expected_source_hash=req.get("expected_source_hash", ""),
            )
            if result.get("ok"):
                validation_saved = rules_api.save_validation_cases(
                    result.get("path", ""), list(req.get("validation_cases") or [])
                )
                if not validation_saved.get("ok"):
                    return validation_saved
                result["validation_cases"] = validation_saved["cases"]
                if req.get("coverage"):
                    coverage_saved = rules_api.save_deployment_coverage_draft(
                        result["id"], dict(req["coverage"])
                    )
                    if not coverage_saved.get("ok"):
                        return coverage_saved
                self.rules_cache.invalidate()
            return result
        if rtype == "save_rule":
            if req.get("strict"):
                valid, error = rules_api.validate_editor_source(req.get("source", ""))
                if not valid:
                    return {"ok": False, "error": error}
            result = rules_api.save_rule(
                req["rule_id"],
                req.get("source", ""),
                req.get("scope", "project"),
                req.get("project_root") or None,
            )
            if result.get("ok"):
                if req.get("new_draft"):
                    rules_api.set_enabled(
                        result["id"], False, req.get("project_root") or None
                    )
                self.rules_cache.invalidate()
                self._warmed.discard(req.get("project_root", ""))
            return result
        if rtype == "rename_rule":
            with self._state_lock:
                known = list(self.known_projects)
            discovered = [
                item["path"] for item in codex_projects.discover_projects(limit=100)
            ]
            result = rules_api.rename_rule(
                req["rule_id"],
                req.get("name", ""),
                project_root=req.get("project_root") or None,
                project_roots=list(dict.fromkeys([*known, *discovered])),
                source_override=req.get("source"),
            )
            if result.get("ok"):
                self.rules_cache.invalidate()
            return result
        if rtype == "create_rule":
            result = rules_api.create_rule(
                req["rule_id"],
                req.get("scope", "project"),
                req.get("project_root") or None,
                req.get("title"),
            )
            if result.get("ok"):
                self.rules_cache.invalidate()
            return result
        if rtype == "add_builtin":
            rule_id = req["rule_id"]
            scope = req.get("scope", "project")
            project_root = req.get("project_root") or None
            source = scaffold.BUILTIN_DIR / f"{rule_id}.py"
            if not source.exists():
                return {"ok": False, "error": f"No built-in rule named {rule_id}."}
            loaded_builtin = load_rule_file(source, "builtin")
            if not loaded_builtin:
                return {"ok": False, "error": "Built-in rule could not be loaded."}
            target = (
                scaffold.rules_dir_for(scope, project_root)
                / loaded_builtin[0].id
                / "rule.py"
            )
            replace = bool(req.get("replace"))
            if target.exists() and not replace:
                return {
                    "ok": False,
                    "error": "A customized rule with this id already exists.",
                    "conflict": True,
                    "path": str(target),
                }
            installed = rules_api.install_builtin(
                rule_id, scope, project_root, overwrite=replace
            )
            if not installed:
                return {"ok": False, "error": "Built-in rule could not be installed."}
            if scope == "global":
                rules_api.set_enabled(loaded_builtin[0].id, False, None)
            self.rules_cache.invalidate()
            return {"ok": True, "id": rule_id, "path": str(installed), "scope": scope}
        if rtype == "convert_rules":
            project_root = req.get("project_root", "")
            scope = req.get("scope", "project")
            notes = scaffold.convert_prose_rules(project_root, scope)
            self.rules_cache.invalidate()
            return {"ok": True, "notes": notes}
        if rtype == "delete_rule":
            with self._state_lock:
                known = list(self.known_projects)
            discovered = [
                item["path"] for item in codex_projects.discover_projects(limit=100)
            ]
            project_roots = list(dict.fromkeys([*known, *discovered]))
            definition = req.get("definition") or {}
            if definition.get("rule_id") not in (None, req["rule_id"]):
                return {"ok": False, "error": "rule definition identity mismatch"}
            result = rules_api.delete_rule_definition(
                req["rule_id"],
                definition.get("scope", ""),
                definition.get("project_root") or None,
                definition.get("source_path", ""),
                definition.get("source_hash", ""),
                project_roots=project_roots,
            )
            if result.get("ok"):
                self.rules_cache.invalidate()
                result["archived_findings"] = self._archive_orphaned_findings(
                    req["rule_id"]
                )
                self.incidents.clear(rule_id=req["rule_id"])
            return result
        if rtype == "stop_rule_everywhere":
            rule_id = req["rule_id"]
            result = rules_api.set_enabled(rule_id, False, None)
            for item in codex_projects.discover_projects(limit=100):
                rules_api.set_enabled(
                    rule_id, False, item["path"], name=req.get("name")
                )
            self.rules_cache.invalidate()
            return result
        if rtype == "customize_for_project":
            result = rules_api.customize_for_project(
                req["rule_id"], req["project_root"]
            )
            if result.get("ok"):
                self.rules_cache.invalidate()
            return result
        if rtype == "revert_to_shared":
            definition = req.get("definition") or {}
            if definition.get("rule_id") not in (None, req["rule_id"]):
                return {"ok": False, "error": "rule definition identity mismatch"}
            result = rules_api.revert_to_shared(
                req["rule_id"],
                req["project_root"],
                definition.get("source_path", ""),
                definition.get("source_hash", ""),
            )
            if result.get("ok"):
                self.rules_cache.invalidate()
            return result
        if rtype == "promote_to_shared":
            result = rules_api.promote_to_shared(req["rule_id"], req["project_root"])
            if result.get("ok"):
                self.rules_cache.invalidate()
            return result
        if rtype == "attach_to_projects":
            return rules_api.attach_to_projects(
                req["rule_id"], list(req.get("project_roots") or [])
            )
        if rtype == "reload":
            self.rules_cache.invalidate()
            with self._state_lock:
                self._warmed.clear()
                self._warm_state.clear()
            return {"ok": True}
        if rtype == "mute":
            return rules_api.set_mute(
                req["rule_id"], req.get("until"), req.get("project_root") or None
            )
        if rtype == "unmute":
            return rules_api.clear_mute(req["rule_id"], req.get("project_root") or None)
        if rtype == "set_rule_enabled":
            project_root = req.get("project_root", "")
            result = rules_api.set_enabled(
                req["rule_id"],
                bool(req.get("enabled")),
                project_root or None,
                req.get("name"),
            )
            self.rules_cache.invalidate()
            with self._state_lock:
                self._warmed.discard(project_root)
                self._warm_state.pop(project_root, None)
            if result.get("ok") and req.get("enabled") and project_root:
                with self._state_lock:
                    self._warmed.add(project_root)
                self.work.submit(self._warm, project_root)
            elif result.get("ok") and not req.get("enabled"):
                self.incidents.clear(
                    project_root=project_root or None, rule_id=req["rule_id"]
                )
            return result
        if rtype == "set_project_monitoring":
            result = rules_api.set_project_enabled(
                req["project_root"], bool(req.get("enabled"))
            )
            if result.get("ok") and req.get("enabled"):
                with self._state_lock:
                    self._warmed.add(req["project_root"])
                self.work.submit(self._warm, req["project_root"])
            elif result.get("ok"):
                self.incidents.clear(project_root=req["project_root"])
            return result
        if rtype == "reset_project_assignments":
            return rules_api.reset_project_assignments(req["project_root"])
        if rtype == "set_project_assignments":
            return rules_api.set_project_assignments(
                req["project_root"],
                {
                    str(key): bool(value)
                    for key, value in (req.get("assignments") or {}).items()
                },
            )
        if rtype == "set_monitoring_paused":
            result = rules_api.set_monitoring_paused(bool(req.get("paused")))
            if result.get("ok") and not req.get("paused"):
                with self._state_lock:
                    projects = list(self.known_projects)
                for project_root in projects:
                    with self._state_lock:
                        self._warmed.add(project_root)
                    self.work.submit(self._warm, project_root)
            return result
        if rtype == "activate_rule":
            rule_id = req["rule_id"]
            project_root = req.get("project_root", "")
            info = rules_api.get_rule(rule_id, project_root or None)
            if not info:
                return {"ok": False, "error": "rule not found"}
            source = info.get("source", "")
            valid, error = rules_api.validate_editor_source(source)
            if not valid:
                return {"ok": False, "error": error}
            rule = self._rule_from(rule_id, project_root, source)
            if rule is None:
                return {"ok": False, "error": "rule could not be loaded"}
            compiled: dict[str, Any] = {}
            if rule.spec:
                compiled = self.compile_rule(rule_id, project_root, source=source)
                if not compiled.get("ok"):
                    return compiled
            compiler_info = dict(compiled.get("compiler_info") or {})
            active = revisions.activate(
                rule.id,
                info["path"],
                source,
                compiler=str(compiled.get("compiler", "")) or None,
                program_id=str(compiled.get("program_id", "")) or None,
                compiler_snapshot=str(compiler_info.get("latest_snapshot", "")) or None,
                compiler_mode=(revisions.EXPLICIT_COMPILER_MODE if rule.spec else None),
            )
            self.rules_cache.invalidate()
            if req.get("enable", True):
                rules_api.set_enabled(rule.id, True, project_root or None)
            return {
                "ok": True,
                "active": active,
                "enabled": bool(req.get("enable", True)),
            }
        if rtype == "compile":
            return self.compile_rule(
                req["rule_id"],
                req.get("project_root", ""),
                bool(req.get("finalize")),
                req.get("source"),
            )
        if rtype == "test":
            return self.test_rule(
                req["rule_id"], req.get("project_root", ""), req.get("source")
            )
        if rtype == "shutdown":
            self._stop.set()
            return {"ok": True}
        return {"ok": False, "error": f"unknown type {rtype!r}"}


class _Handler(socketserver.StreamRequestHandler):
    daemon_ref: "Daemon"

    def handle(self) -> None:
        try:
            line = self.rfile.readline()
            if not line:
                return
            req = json.loads(line.decode("utf-8"))
        except (json.JSONDecodeError, ValueError):
            self.wfile.write(b'{"ok": false, "error": "bad json"}\n')
            return
        try:
            resp = self.daemon_ref.dispatch(req)
        except Exception as exc:  # pragma: no cover - defensive
            resp = {"ok": False, "error": repr(exc)}
        self.wfile.write((json.dumps(resp) + "\n").encode("utf-8"))


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True
    # Codex can start many hook clients together (for example, after a burst of
    # parallel tool calls).  ``socketserver`` otherwise inherits a backlog of
    # only five, allowing connection attempts to fail before the daemon can
    # durably admit their events.
    request_queue_size = 128


_daemon_lock_handle = None


def _single_instance_or_exit() -> None:
    global _daemon_lock_handle
    lock = config.state_dir() / "daemon.lock"
    handle = lock.open("a+")
    if fcntl is not None:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print("daemon already starting or running", file=sys.stderr)
            sys.exit(0)
    _daemon_lock_handle = handle
    from . import ipc

    if ipc.ping():
        print("daemon already running", file=sys.stderr)
        sys.exit(0)
    sock = config.socket_path()
    if sock.exists():
        sock.unlink(missing_ok=True)


def run() -> None:
    _single_instance_or_exit()
    daemon = Daemon()
    _Handler.daemon_ref = daemon
    config.pid_path().write_text(str(os.getpid()))
    server = _Server(str(config.socket_path()), _Handler)
    _log(f"daemon started pid={os.getpid()} paw_available={daemon.runtime.available}")

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        while not daemon._stop.is_set():
            daemon._stop.wait(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        daemon.runtime.shutdown()
        Path(config.socket_path()).unlink(missing_ok=True)
        config.pid_path().unlink(missing_ok=True)
        _log("daemon stopped")


if __name__ == "__main__":
    run()
