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
import socketserver
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from . import __version__, config, paw_runtime, rules_api, scaffold
from .adapters.cursor import projects as cursor_projects
from .core import audit
from .core.attention import AttentionStore
from .core.engine import Engine, RuleContext
from .core.events import (
    Event, MESSAGE, QUESTION_REQUEST, SESSION_START, SESSION_STOP, USER_PROMPT,
)
from .core.ledger import LedgerStore
from .core import revisions
from .core.rule import (
    LoadedRule, RuleLoadError, load_rule_file, load_rules_with_errors, rule_paths,
)
from .core.store import VerdictStore
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
        self._cache: dict[
            str, tuple[float, list[LoadedRule], list[RuleLoadError]]
        ] = {}
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
                    active_rule.slug = rule.slug
                    active_rule.source_path = info["cache_path"]
                    active_rule.working_source_path = rule.source_path
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
    def __init__(self) -> None:
        self.started_at = time.time()
        self.runtime = paw_runtime.shared()
        self.store = VerdictStore()
        self.attention = AttentionStore()
        self.ledgers = LedgerStore()
        self.rules_cache = _RulesCache()
        self.engine = Engine(
            self.runtime, self.store, self.rules_cache.get,
            on_verdict=self._on_verdict,
            is_muted=rules_api.is_muted, is_enabled=rules_api.is_enabled,
        )
        self.work = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rap-work")
        self._warmed: set[str] = set()
        self.known_projects: set[str] = set()
        self._state_lock = threading.Lock()
        self._warm_state: dict[str, dict[str, dict[str, Any]]] = {}
        self._project_activity: dict[str, dict[str, Any]] = {}
        self._last_successful_audit = 0.0
        self._stop = threading.Event()

    # --- event handling --------------------------------------------------
    def handle_event(self, ev_dict: dict[str, Any]) -> None:
        event = Event.from_dict(ev_dict)
        if event.project_root:
            with self._state_lock:
                self.known_projects.add(event.project_root)
                activity = self._project_activity.setdefault(event.project_root, {})
                previous_generation = activity.get("generation_id", "")
                activity.update({
                    "last_event_ts": event.ts,
                    "last_event_kind": event.kind,
                    "conversation_id": event.conversation_id,
                    "generation_id": event.generation_id,
                })
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
                conversation_id=event.conversation_id, reason="user replied")
        if rules_api.monitoring_paused():
            return
        if event.project_root and not rules_api.project_enabled(event.project_root):
            return  # monitoring is off for this project
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
        if (
            event.kind == SESSION_STOP
            and event.payload.get("status", "completed") == "completed"
        ):
            self.work.submit(self._evaluate_attention, event, ledger)
        should_warm = False
        if event.kind == SESSION_START:
            with self._state_lock:
                if event.project_root not in self._warmed:
                    self._warmed.add(event.project_root)
                    should_warm = True
        if should_warm:
            self.work.submit(self._warm, event.project_root)

    def _evaluate(self, event: Event, ledger) -> None:
        try:
            self.engine.on_event(event, ledger)
        except Exception as exc:
            _log(f"evaluate error: {exc!r}")

    def _evaluate_attention(self, event: Event, ledger) -> None:
        rule_id = "agent-needs-reply"
        if not self._rule_enabled(rule_id, event.project_root):
            return
        try:
            rule = self._rule_from(rule_id, event.project_root, None)
            if rule is None or rule.channel != "attention":
                return
            context = RuleContext(ledger, self.runtime, rule.inputs)
            result = rule.fn(context)
            if not result:
                return
            latest = ledger.latest_text(MESSAGE)
            self.attention.set(
                project_root=event.project_root,
                conversation_id=event.conversation_id,
                generation_id=event.generation_id,
                message=latest or str(result),
                confidence="inferred",
                source=rule_id,
            )
        except Exception as exc:
            _log(f"attention evaluate error: {exc!r}")

    def _warm(self, project_root: str) -> None:
        rules = list(self.rules_cache.get(project_root))
        if not any(rule.id == "agent-needs-reply" for rule in rules):
            attention_rule = self._rule_from(
                "agent-needs-reply", project_root, None)
            if attention_rule is not None:
                rules.append(attention_rule)
        with self._state_lock:
            project_state = self._warm_state.setdefault(project_root, {})
            for rule in rules:
                project_state[rule.id] = {
                    "status": "disabled" if not self._rule_enabled(rule.id, project_root)
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
                    self._set_warm_state(project_root, rule.id, "ready")
                    results[rule.id] = True
                    continue
                if not self.runtime.available:
                    self._set_warm_state(
                        project_root, rule.id, "failed", "PAW SDK is unavailable")
                    results[rule.id] = False
                    continue
                pid = self.runtime.program_id_for_spec(rule.spec, None)
                if not pid:
                    self._set_warm_state(
                        project_root, rule.id, "failed", "Rule compilation failed")
                    results[rule.id] = False
                    continue
                ok = self.runtime.warm(pid)
                self._set_warm_state(
                    project_root, rule.id, "ready" if ok else "failed",
                    "" if ok else "Local PAW model failed to warm")
                results[rule.id] = ok
            _log(f"warmed {project_root}: {results}")
        except Exception as exc:
            _log(f"warm error: {exc!r}")
            with self._state_lock:
                state = self._warm_state.setdefault(project_root, {})
                for rule in rules:
                    if state.get(rule.id, {}).get("status") == "warming":
                        state[rule.id] = {
                            "status": "failed",
                            "updated_at": time.time(),
                            "error": str(exc),
                        }

    @staticmethod
    def _rule_enabled(rule_id: str, project_root: str) -> bool:
        """Compatibility shim while state migrated from global to scoped keys."""
        try:
            return bool(rules_api.is_enabled(rule_id, project_root))
        except TypeError:  # pragma: no cover - old state API during upgrades
            return bool(rules_api.is_enabled(rule_id))

    def _set_warm_state(
        self, project_root: str, rule_id: str, status: str, error: str = ""
    ) -> None:
        with self._state_lock:
            self._warm_state.setdefault(project_root, {})[rule_id] = {
                "status": status,
                "updated_at": time.time(),
                "error": error,
            }

    def _on_verdict(self, verdict) -> None:
        with self._state_lock:
            self._last_successful_audit = verdict.ts
        _log(f"verdict [{verdict.severity}] {verdict.rule_id}: {verdict.message}")

    # --- status snapshot -------------------------------------------------
    @staticmethod
    def _hooks_installed(project_root: str) -> bool:
        """Check for our hook in either project or global Cursor config."""
        for path in (
            config.cursor_hooks_path("project", project_root),
            config.cursor_hooks_path("global"),
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
        discovered = cursor_projects.discover_projects(limit=100)
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
            elif not hooks or not rules:
                status = "setup_needed"
            elif not enabled:
                status = "disabled"
            elif has_paw and not self.runtime.available:
                status = "failed"
            elif load_errors and not rules:
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
            out.append({
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
                    1 for item in attention if item.get("project_root") == path),
                "warm": warm_states,
            })
        out.sort(
            key=lambda item: (
                bool(item["active"]),
                item["last_event_ts"] or item["workspace_mtime"],
            ),
            reverse=True,
        )
        return out

    def snapshot(self) -> dict[str, Any]:
        all_findings = self.store.by_project()
        active_findings: dict[str, list[dict[str, Any]]] = {}
        stale_findings: dict[str, list[dict[str, Any]]] = {}
        for project_root, groups in all_findings.items():
            summaries = {
                rule["id"]: rule for rule in rules_api.list_rules(project_root)
            }
            for group in groups:
                summary = summaries.get(group.get("rule_id"), {})
                current_hash = (
                    summary.get("active_hash") or summary.get("working_hash") or ""
                )
                recorded_hash = group.get("source_hash") or ""
                stale = bool(
                    recorded_hash and current_hash and recorded_hash != current_hash)
                group["stale"] = stale
                group["current_source_hash"] = current_hash
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
        statuses = {item["status"] for item in projects}
        paused = rules_api.monitoring_paused()
        if paused:
            health = "paused"
        elif "failed" in statuses or "degraded" in statuses:
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
            },
            "projects": projects,
            "findings_by_project": combined,
            "stale_findings_by_project": stale_findings,
            "attention": attention,
            "attention_count": len(attention),
            "open_count": sum(len(rows) for rows in active_findings.values()),
            "stale_count": sum(len(rows) for rows in stale_findings.values()),
            "project_count": sum(1 for p in projects if p["monitoring"]),
        }

    # --- PAW-backed rule operations (use the warm runtime) ---------------
    def _rule_from(self, rule_id: str, project_root: str,
                   source: str | None) -> LoadedRule | None:
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

    def compile_rule(self, rule_id: str, project_root: str, finalize: bool = False,
                     source: str | None = None) -> dict[str, Any]:
        if not self.runtime.available:
            return {"ok": False, "error": "PAW SDK not available"}
        rule = self._rule_from(rule_id, project_root, source)
        if rule is None or not rule.spec:
            return {"ok": False, "error": "rule has no PAW spec"}
        compiler = "paw-ft-bs48" if finalize else None
        self._set_warm_state(project_root, rule.id, "warming")
        pid = self.runtime.program_id_for_spec(rule.spec, compiler)
        if not pid:
            self._set_warm_state(
                project_root, rule.id, "failed", "Compilation failed or timed out")
            return {"ok": False, "error": "compile failed or timed out"}
        warmed = self.runtime.warm(pid)
        self._set_warm_state(
            project_root, rule.id, "ready" if warmed else "failed",
            "" if warmed else "Local PAW model failed to warm")
        if not warmed:
            return {"ok": False, "error": "compiled, but local model failed to warm"}
        return {"ok": True, "program_id": pid, "finalized": finalize}

    def test_rule(self, rule_id: str, project_root: str,
                  source: str | None = None) -> dict[str, Any]:
        if not self.runtime.available:
            return {"ok": False, "error": "PAW SDK not available"}
        rule = self._rule_from(rule_id, project_root, source)
        if rule is None:
            return {"ok": False, "error": "rule not found"}
        cases = list(rule.examples) or rules_api.spec_examples(rule.spec)
        if not rule.spec or not cases:
            return {"ok": True, "results": [], "passed": 0, "total": 0,
                    "note": "no PAW spec Input/Output cases to test"}
        pid = self.runtime.program_id_for_spec(rule.spec, None)
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
                self.handle_event(ev)
            return {"ok": True}
        if rtype == "warm":
            proj = req.get("project_root", "")
            if proj:
                with self._state_lock:
                    self.known_projects.add(proj)
            self.work.submit(self._warm, proj)
            return {"ok": True}
        if rtype == "verdicts":
            return {"ok": True, "verdicts": self.store.recent(
                limit=int(req.get("limit", 100)), project_root=req.get("project_root"),
                include_acknowledged=bool(req.get("include_acknowledged")),
                include_suppressed=bool(req.get("include_suppressed")))}
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
            return {"ok": True, "groups": groups}
        if rtype == "finding_detail":
            finding_id = int(req.get("id", 0))
            finding = self.store.get(finding_id)
            if not finding:
                return {"ok": False, "error": "finding not found"}
            entry = audit.read_finding(
                finding["project_root"],
                finding_id,
                rule_id=finding.get("rule_id"),
                ts=finding.get("ts"),
            )
            current_rule = rules_api.get_rule(
                finding["rule_id"], finding["project_root"]) or {}
            current_source = str(current_rule.get("source", ""))
            working_hash = (
                hashlib.sha256(current_source.encode("utf-8")).hexdigest()
                if current_source else ""
            )
            current_hash = current_rule.get("active_hash") or working_hash
            ledger = self.ledgers.get(
                finding.get("conversation_id", ""), finding["project_root"])
            ledger_window = ledger.context_window(
                finding.get("trigger_event_id", ""),
                center_ts=finding.get("ts"),
                before=30,
                after=30,
            )
            return {
                "ok": True,
                "finding": finding,
                "trace": (entry or {}).get("trace", []),
                "audit": entry,
                "ledger": ledger_window,
                "current_rule": current_rule,
                "current_rule_hash": current_hash,
                "working_rule_hash": working_hash,
                "rule_changed": bool(
                    entry and entry.get("rule_source_hash")
                    and current_hash
                    and entry.get("rule_source_hash") != current_hash),
                "occurrences": self.store.occurrences(
                    finding.get("fingerprint", ""), limit=100),
            }
        if rtype == "ledger_window":
            finding = self.store.get(int(req.get("id", 0)))
            if not finding:
                return {"ok": False, "error": "finding not found"}
            ledger = self.ledgers.get(
                finding.get("conversation_id", ""), finding["project_root"])
            return {
                "ok": True,
                "ledger": ledger.context_window(
                    finding.get("trigger_event_id", ""),
                    center_ts=finding.get("ts"),
                    start=int(req.get("start", 0)),
                    limit=int(req.get("limit", 60)),
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
                ids=req.get("ids"), fingerprint=req.get("fingerprint"))
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
        if rtype == "rules":
            project_root = req.get("project_root", "")
            errors = self.rules_cache.errors(project_root)
            rules = rules_api.list_rules(project_root or None)
            project_paths = [
                item["path"] for item in cursor_projects.discover_projects(limit=100)
            ]
            with self._state_lock:
                warm = {
                    rid: dict(value)
                    for rid, value in self._warm_state.get(project_root, {}).items()
                }
            for rule in rules:
                state = warm.get(rule["id"], {})
                rule["warm_status"] = state.get(
                    "status", "disabled" if not rule.get("enabled") else "idle")
                rule["warm_error"] = state.get("error", "")
                if rule.get("source_origin") == "project":
                    rule["usage_count"] = (
                        1 if rules_api.is_enabled(rule["id"], project_root) else 0
                    )
                else:
                    rule["usage_count"] = sum(
                        1 for path in project_paths
                        if rules_api.is_enabled(rule["id"], path)
                    )
            return {
                "ok": True,
                "rules": rules,
                "errors": [
                    {"path": error.path, "scope": error.scope, "error": error.error}
                    for error in errors
                ],
                "builtins": scaffold.builtin_ids(),
            }
        if rtype == "rule_get":
            info = rules_api.get_rule(
                req["rule_id"], req.get("project_root") or None)
            if info:
                info["projection"] = rules_api.source_projection(
                    info.get("source", ""))
            return {"ok": bool(info), "rule": info,
                    **({} if info else {"error": "rule not found"})}
        if rtype == "validate_rule":
            if req.get("strict"):
                valid, error = rules_api.validate_editor_source(
                    req.get("source", ""))
            else:
                valid, error = rules_api.check_source_syntax(req.get("source", ""))
            return {"ok": valid, "error": error}
        if rtype == "new_rule_draft":
            project_root = req.get("project_root", "")
            if not project_root:
                return {"ok": False, "error": "project_root is required"}
            existing = {rule["id"] for rule in rules_api.list_rules(project_root)}
            rule_id = str(uuid.uuid4())
            while rule_id in existing or (
                config.project_rules_dir(project_root) / rule_id / "rule.py"
            ).exists():
                rule_id = str(uuid.uuid4())
            template = req.get("template", "paw")
            source = (
                rules_api.draft_plain_rule_source(rule_id)
                if template == "python"
                else rules_api.draft_rule_source(rule_id)
            )
            return {
                "ok": True,
                "rule": {
                    "id": rule_id,
                    "title": (
                        "Flag a deterministic text pattern."
                        if template == "python"
                        else "Use Git for source synchronization."
                    ),
                    "scope": "project",
                    "project_root": project_root,
                    "source": source,
                    "projection": rules_api.source_projection(source),
                    "path": "",
                    "enabled": False,
                    "muted": False,
                    "new_draft": True,
                },
            }
        if rtype == "save_rule":
            if req.get("strict"):
                valid, error = rules_api.validate_editor_source(
                    req.get("source", ""))
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
                        result["id"], False, req.get("project_root") or None)
                self.rules_cache.invalidate()
                self._warmed.discard(req.get("project_root", ""))
            return result
        if rtype == "rename_rule":
            with self._state_lock:
                known = list(self.known_projects)
            discovered = [
                item["path"] for item in cursor_projects.discover_projects(limit=100)
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
                / loaded_builtin[0].id / "rule.py"
            )
            replace = bool(req.get("replace"))
            if target.exists() and not replace:
                return {
                    "ok": False,
                    "error": "A customized rule with this id already exists.",
                    "conflict": True,
                    "path": str(target),
                }
            installed = scaffold.add_builtin(
                rule_id, scope, project_root, overwrite=replace)
            if not installed:
                return {"ok": False, "error": "Built-in rule could not be installed."}
            self.rules_cache.invalidate()
            return {"ok": True, "id": rule_id, "path": str(installed), "scope": scope}
        if rtype == "convert_rules":
            project_root = req.get("project_root", "")
            scope = req.get("scope", "project")
            notes = scaffold.convert_prose_rules(project_root, scope)
            self.rules_cache.invalidate()
            return {"ok": True, "notes": notes}
        if rtype == "delete_rule":
            result = rules_api.delete_rule(
                req["rule_id"], req.get("project_root") or None)
            if result.get("ok"):
                self.rules_cache.invalidate()
            return result
        if rtype == "customize_for_project":
            result = rules_api.customize_for_project(
                req["rule_id"], req["project_root"])
            if result.get("ok"):
                self.rules_cache.invalidate()
            return result
        if rtype == "revert_to_shared":
            result = rules_api.revert_to_shared(
                req["rule_id"], req["project_root"])
            if result.get("ok"):
                self.rules_cache.invalidate()
            return result
        if rtype == "promote_to_shared":
            result = rules_api.promote_to_shared(
                req["rule_id"], req["project_root"])
            if result.get("ok"):
                self.rules_cache.invalidate()
            return result
        if rtype == "attach_to_projects":
            return rules_api.attach_to_projects(
                req["rule_id"], list(req.get("project_roots") or []))
        if rtype == "reload":
            self.rules_cache.invalidate()
            with self._state_lock:
                self._warmed.clear()
                self._warm_state.clear()
            return {"ok": True}
        if rtype == "mute":
            return rules_api.set_mute(
                req["rule_id"], req.get("until"), req.get("project_root") or None)
        if rtype == "snooze":
            return rules_api.snooze(
                req["rule_id"], float(req.get("seconds", 3600)),
                req.get("project_root") or None)
        if rtype == "unmute":
            return rules_api.clear_mute(
                req["rule_id"], req.get("project_root") or None)
        if rtype == "set_rule_enabled":
            project_root = req.get("project_root", "")
            result = rules_api.set_enabled(
                req["rule_id"], bool(req.get("enabled")),
                project_root or None, req.get("name"))
            self.rules_cache.invalidate()
            with self._state_lock:
                self._warmed.discard(project_root)
                self._warm_state.pop(project_root, None)
            if result.get("ok") and req.get("enabled") and project_root:
                with self._state_lock:
                    self._warmed.add(project_root)
                self.work.submit(self._warm, project_root)
            return result
        if rtype == "set_project_monitoring":
            result = rules_api.set_project_enabled(
                req["project_root"], bool(req.get("enabled")))
            if result.get("ok") and req.get("enabled"):
                with self._state_lock:
                    self._warmed.add(req["project_root"])
                self.work.submit(self._warm, req["project_root"])
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
            if rule.spec:
                tested = self.test_rule(rule_id, project_root, source)
                if not tested.get("ok"):
                    return tested
                if tested.get("total") and tested.get("passed") != tested.get("total"):
                    return {
                        "ok": False,
                        "error": (
                            f"{tested.get('passed', 0)}/{tested.get('total', 0)} "
                            "PAW cases passed"
                        ),
                        "test": tested,
                    }
                compiled = self.compile_rule(rule_id, project_root, source=source)
                if not compiled.get("ok"):
                    return compiled
            active = revisions.activate(rule.id, info["path"], source)
            self.rules_cache.invalidate()
            if req.get("enable", True):
                rules_api.set_enabled(rule.id, True, project_root or None)
            return {"ok": True, "active": active, "enabled": bool(req.get("enable", True))}
        if rtype == "compile":
            return self.compile_rule(req["rule_id"], req.get("project_root", ""),
                                     bool(req.get("finalize")), req.get("source"))
        if rtype == "test":
            return self.test_rule(req["rule_id"], req.get("project_root", ""), req.get("source"))
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


def _single_instance_or_exit() -> None:
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
