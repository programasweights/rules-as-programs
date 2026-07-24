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
from .core.incidents import IncidentStore
from .core import revisions
from .core.rule import (
    LoadedRule, RuleLoadError, load_rule_file, load_rules_with_errors,
    new_rule_id, rule_paths,
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
                    active_rule.source_path = info["cache_path"]
                    active_rule.working_source_path = rule.source_path
                    active_rule.compiler = str(info.get("compiler", ""))
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
    def __init__(self) -> None:
        self.started_at = time.time()
        self.runtime = paw_runtime.shared()
        self.store = VerdictStore()
        self.attention = AttentionStore()
        self.incidents = IncidentStore()
        self.ledgers = LedgerStore()
        self.rules_cache = _RulesCache()
        self.engine = Engine(
            self.runtime, self.store, self.rules_cache.get,
            on_verdict=self._on_verdict,
            on_error=self._on_rule_error,
            on_success=self._on_rule_success,
            is_muted=rules_api.is_muted, is_enabled=rules_api.is_enabled,
        )
        self.work = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rap-work")
        self._warmed: set[str] = set()
        self.known_projects: set[str] = set()
        self._state_lock = threading.Lock()
        self._warm_state: dict[str, dict[str, dict[str, Any]]] = {}
        self._warm_generation: dict[str, int] = {}
        self._project_activity: dict[str, dict[str, Any]] = {}
        self._prepared_deployments: dict[str, dict[str, Any]] = {}
        self._deployment_lock = threading.Lock()
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
        rule_id = "gn3xtat6av4fy690"
        if not self._rule_enabled(rule_id, event.project_root):
            return
        try:
            rule = next(
                (item for item in self.rules_cache.get(event.project_root)
                 if item.id == rule_id),
                None,
            )
            if rule is None or rule.channel != "attention":
                return
            context = RuleContext(
                ledger, self.runtime, rule.inputs, rule.probes,
                rule.compiler or None)
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
                    self._set_warm_state(
                        project_root, rule.id, "ready", generation=generation)
                    results[rule.id] = True
                    continue
                if not self.runtime.available:
                    self._set_warm_state(
                        project_root, rule.id, "failed", "PAW SDK is unavailable",
                        generation=generation)
                    results[rule.id] = False
                    continue
                pid = self.runtime.program_id_for_spec(
                    rule.spec, rule.compiler or None)
                if not pid:
                    self._set_warm_state(
                        project_root, rule.id, "failed", "Rule compilation failed",
                        generation=generation)
                    results[rule.id] = False
                    continue
                ok = self.runtime.warm(pid)
                self._set_warm_state(
                    project_root, rule.id, "ready" if ok else "failed",
                    "" if ok else "Local PAW model failed to warm",
                    generation=generation)
                results[rule.id] = ok
            with self._state_lock:
                if self._warm_generation.get(project_root) != generation:
                    return
            for rule in rules:
                if not self._rule_enabled(rule.id, project_root):
                    continue
                if results.get(rule.id):
                    self.incidents.clear(
                        project_root=project_root, rule_id=rule.id,
                        code="warm_failure")
                    continue
                state = self._warm_state.get(
                    project_root, {}).get(rule.id, {})
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
                            summary=(
                                f"{rule.title} could not prepare its local model"),
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
        self, project_root: str, rule_id: str, status: str, error: str = "",
        *, generation: int | None = None,
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
        _log(f"verdict [{verdict.severity}] {verdict.rule_id}: {verdict.message}")

    def _on_rule_error(
        self, rule: LoadedRule, project_root: str, message: str
    ) -> None:
        code = (
            "invalid_output"
            if "invalid fuzzy severity" in message
            else "runtime_exception"
        )
        summary = (
            f"{rule.title} check returned no valid decision"
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
            threshold=2,
        )
        _log(f"rule error {rule.id} project={project_root}: {message}")

    def _on_rule_success(self, rule: LoadedRule, project_root: str) -> None:
        for code in ("invalid_output", "runtime_exception"):
            self.incidents.clear(
                code=code, project_root=project_root, rule_id=rule.id)
        with self._state_lock:
            self._last_successful_audit = time.time()

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
                        candidate_id, project_root, reason="rule_deleted")
        return archived

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
                current_hash = (
                    summary.get("active_hash") or summary.get("working_hash") or ""
                )
                recorded_hash = group.get("source_hash") or ""
                stale = bool(
                    recorded_hash and recorded_hash != current_hash)
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
        health_issues = self.incidents.active()
        import_groups: dict[tuple[str, str], dict[str, Any]] = {}
        for project in projects:
            for error in project.get("rule_errors", []):
                rule_name = Path(error.get("path", "")).parent.name
                key = (rule_name, str(error.get("error", "")))
                issue = import_groups.setdefault(key, {
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
                })
                if project["path"] not in issue["affected_projects"]:
                    issue["affected_projects"].append(project["path"])
            if (
                not project.get("hooks_installed")
                and project.get("rule_count")
                and project.get("monitoring")
            ):
                health_issues.append({
                    "code": "hooks_missing",
                    "project_root": project["path"],
                    "rule_id": "",
                    "rule_name": "",
                    "summary": f"Auditing is not connected to {project['name']}",
                    "detail": "Cursor hooks are missing or invalid.",
                    "impact": "agent activity is not being audited",
                    "count": 1,
                    "threshold": 1,
                    "affected_projects": [project["path"]],
                })
        for issue in import_groups.values():
            affected = len(issue["affected_projects"])
            if affected > 1:
                issue["summary"] = (
                    f"{issue['rule_name'] or 'A rule'} could not load in "
                    f"{affected} projects")
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
                  source: str | None = None,
                  compiler: str | None = None) -> dict[str, Any]:
        if not self.runtime.available:
            return {"ok": False, "error": "PAW SDK not available"}
        rule = self._rule_from(rule_id, project_root, source)
        if rule is None:
            return {"ok": False, "error": "rule not found"}
        cases = list(rule.examples) or rules_api.spec_examples(rule.spec)
        if not rule.spec or not cases:
            return {"ok": True, "results": [], "passed": 0, "total": 0,
                    "note": "no PAW spec Input/Output cases to test"}
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

    def _project_catalog(self) -> list[dict[str, str]]:
        discovered = cursor_projects.discover_projects(limit=100)
        by_path = {
            str(item["path"]): {
                "path": str(item["path"]),
                "name": str(item.get("name") or Path(item["path"]).name),
            }
            for item in discovered if item.get("path")
        }
        with self._state_lock:
            known = list(self.known_projects)
        for path in known:
            by_path.setdefault(path, {"path": path, "name": Path(path).name})
        return sorted(
            by_path.values(), key=lambda item: item["name"].lower())

    def deployment_plan(
        self, rule_id: str, project_root: str = ""
    ) -> dict[str, Any]:
        projects = self._project_catalog()
        if project_root and all(
            item["path"] != project_root for item in projects
        ):
            projects.append({
                "path": project_root,
                "name": Path(project_root).name,
            })
            projects.sort(key=lambda item: item["name"].lower())
        roots = [item["path"] for item in projects]
        info = rules_api.get_rule(rule_id, project_root or None)
        if info and info.get("scope") == "builtin":
            info = None
        coverage = (
            rules_api.rule_coverage(rule_id, roots)
            if info else {
                "mode": "selected",
                "all_projects": False,
                "selected_projects": [project_root] if project_root else [],
            }
        )
        draft_coverage = rules_api.deployment_coverage_draft(rule_id)
        source_path = str(
            ((info or {}).get("definition") or {}).get("source_path", ""))
        consumers = []
        overrides = []
        for root in roots:
            effective = rules_api.get_rule(rule_id, root)
            effective_path = str(
                ((effective or {}).get("definition") or {}).get(
                    "source_path", ""))
            if effective and effective.get("scope") == "project":
                overrides.append(root)
            if source_path and effective_path == source_path and rules_api.is_enabled(
                rule_id, root
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
        coverage_roots = [
            item["path"] for item in self._project_catalog()]
        expected_coverage = (
            rules_api.rule_coverage(rule_id, coverage_roots)
            if current else {
                "mode": "selected",
                "all_projects": False,
                "selected_projects": [],
            }
        )
        expected_active_hash = str(
            req.get("expected_active_hash", "")
            if "expected_active_hash" in req
            else current_active.get("source_hash", ""))
        source_changed = bool(req.get("source_changed", True))
        compiler = str(
            req.get("compiler")
            if req.get("compiler") is not None
            else current_active.get("compiler", ""))
        tested = {"ok": True, "results": [], "passed": 0, "total": 0}
        program_id = str(current_active.get("program_id", ""))
        if source_changed or not current_active:
            rule = self._rule_from(rule_id, project_root, source)
            if rule is None:
                return {"ok": False, "error": "rule could not be loaded"}
            if rule.spec:
                tested = self.test_rule(
                    rule_id, project_root, source, compiler or None)
                if not tested.get("ok"):
                    return tested
                if tested.get("total") and tested.get("passed") != tested.get("total"):
                    return {
                        "ok": False,
                        "error": (
                            f"{tested.get('passed', 0)}/"
                            f"{tested.get('total', 0)} examples passed"),
                        "test": tested,
                    }
                compiled = self.compile_rule(
                    rule_id,
                    project_root,
                    finalize=compiler == "paw-ft-bs48",
                    source=source,
                )
                if not compiled.get("ok"):
                    return compiled
                program_id = str(compiled.get("program_id", ""))
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
            "program_id": program_id,
            "coverage": dict(req.get("coverage") or {}),
            "source_changed": source_changed,
            "created_at": time.time(),
            "test": tested,
        }
        with self._state_lock:
            self._prepared_deployments[token] = prepared
        return {
            "ok": True,
            "token": token,
            "source_hash": prepared["source_hash"],
            "test": tested,
            "program_id": program_id,
        }

    def commit_rule_deployment(self, token: str) -> dict[str, Any]:
        with self._deployment_lock:
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
            if (
                str(current_definition.get("source_path", ""))
                != str(prepared_definition.get("source_path", ""))
                or str(current_definition.get("source_hash", ""))
                != str(prepared_definition.get("source_hash", ""))
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
        migrated_to_library = bool(
            current and current.get("scope") == "project")
        if migrated_to_library and (
            config.global_rules_dir() / rule_id / "rule.py"
        ).exists():
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
        previous_active = revisions.active_info(rule_id, path)
        active = (
            revisions.activate(
                rule_id,
                path,
                saved["source"],
                compiler=prepared.get("compiler") or None,
                program_id=prepared.get("program_id") or None,
            )
            if prepared.get("source_changed") or not previous_active
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
                    selected_before = set(
                        old_coverage.get("selected_projects") or [])
                    for root in roots:
                        rules_api.set_enabled(
                            rule_id,
                            all_projects or root in selected_before,
                            root,
                            name=str(saved.get("name", "")))
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
                    selected_before = set(
                        old_coverage.get("selected_projects") or [])
                    for root in roots:
                        rules_api.set_enabled(
                            rule_id,
                            all_projects or root in selected_before,
                            root,
                            name=str(saved.get("name", "")))
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
                ((effective or {}).get("definition") or {}).get(
                    "source_path", ""))
            if effective_path and str(Path(effective_path).resolve()) == canonical_path:
                affected.append(root)
        for root in affected:
            with self._state_lock:
                self._warmed.add(root)
            self.work.submit(self._warm, root)
        return {
            "ok": True,
            "rule": rules_api.get_rule(rule_id, None),
            "active": active,
            "coverage": coverage,
            "affected_projects": affected,
            "impact_count": len(affected),
            "migrated_to_library": migrated_to_library,
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
                self.handle_event(ev)
            return {"ok": True}
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
            recorded_source = str((entry or {}).get("rule_source", ""))
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
                "current_rule_projection": rules_api.source_projection(
                    current_source) if current_source else {},
                "recorded_rule_projection": rules_api.source_projection(
                    recorded_source) if recorded_source else {},
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
        if rtype == "rule_library":
            discovered = [
                item["path"] for item in cursor_projects.discover_projects(limit=100)
            ]
            with self._state_lock:
                known = list(self.known_projects)
            project_paths = list(dict.fromkeys([*known, *discovered]))
            rules, errors = rules_api.list_rule_library_with_errors(
                project_paths)
            builtin_ids = set(scaffold.builtin_ids())
            for rule in rules:
                if rule.get("source_origin") == "project":
                    root = rule.get("project_root", "")
                    rule["usage_count"] = (
                        1 if root and rules_api.is_enabled(rule["id"], root) else 0
                    )
                else:
                    rule["usage_count"] = sum(
                        1 for root in project_paths
                        if rules_api.is_enabled(rule["id"], root)
                    )
            for error in errors:
                error["is_builtin"] = error.get("id") in builtin_ids
                if error.get("scope") == "project":
                    root = error.get("project_root", "")
                    error["usage_count"] = (
                        1 if root and rules_api.is_enabled(
                            error["id"], root) else 0)
                else:
                    error["usage_count"] = sum(
                        1 for root in project_paths
                        if rules_api.is_enabled(error["id"], root))
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
                item["path"] for item in cursor_projects.discover_projects(limit=100)
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
                        1 for path in project_paths
                        if rules_api.is_enabled(summary["id"], path))
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
            info = rules_api.get_rule(
                req["rule_id"], project_root or None)
            if info:
                info["projection"] = rules_api.source_projection(
                    info.get("source", ""))
                info["is_builtin"] = info["id"] in set(scaffold.builtin_ids())
                info["deployment"] = self.deployment_plan(
                    info["id"], project_root)
            return {"ok": bool(info), "rule": info,
                    **({} if info else {"error": "rule not found"})}
        if rtype == "deployment_plan":
            return self.deployment_plan(
                req["rule_id"], req.get("project_root", ""))
        if rtype == "prepare_deployment":
            return self.prepare_rule_deployment(req)
        if rtype == "commit_deployment":
            return self.commit_rule_deployment(str(req.get("token", "")))
        if rtype == "validate_rule":
            if req.get("strict"):
                valid, error = rules_api.validate_editor_source(
                    req.get("source", ""))
            else:
                valid, error = rules_api.check_source_syntax(req.get("source", ""))
            return {"ok": valid, "error": error}
        if rtype == "new_rule_draft":
            project_root = req.get("project_root", "")
            existing = {rule["id"] for rule in rules_api.list_rules(None)}
            rule_id = new_rule_id()
            while rule_id in existing or (
                config.global_rules_dir() / rule_id / "rule.py"
            ).exists():
                rule_id = new_rule_id()
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
                    "scope": "global",
                    "project_root": project_root,
                    "source": source,
                    "projection": rules_api.source_projection(source),
                    "path": "",
                    "enabled": False,
                    "muted": False,
                    "new_draft": True,
                    "deployment": self.deployment_plan(
                        rule_id, project_root),
                },
            }
        if rtype == "save_library_draft":
            valid, error = rules_api.validate_editor_source(
                req.get("source", ""))
            if not valid:
                return {"ok": False, "error": error}
            result = rules_api.save_library_draft(
                req["rule_id"],
                req.get("source", ""),
                expected_source_hash=req.get("expected_source_hash", ""),
                expected_absent=bool(req.get("expected_absent")),
            )
            if result.get("ok"):
                if req.get("coverage"):
                    coverage_saved = rules_api.save_deployment_coverage_draft(
                        result["id"], dict(req["coverage"]))
                    if not coverage_saved.get("ok"):
                        return coverage_saved
                self.rules_cache.invalidate()
            return result
        if rtype == "save_project_draft":
            valid, error = rules_api.validate_editor_source(
                req.get("source", ""))
            if not valid:
                return {"ok": False, "error": error}
            result = rules_api.save_project_draft(
                req["rule_id"],
                req.get("source", ""),
                req["project_root"],
                expected_source_hash=req.get("expected_source_hash", ""),
            )
            if result.get("ok"):
                if req.get("coverage"):
                    coverage_saved = rules_api.save_deployment_coverage_draft(
                        result["id"], dict(req["coverage"]))
                    if not coverage_saved.get("ok"):
                        return coverage_saved
                self.rules_cache.invalidate()
            return result
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
            installed = rules_api.install_builtin(
                rule_id, scope, project_root, overwrite=replace)
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
                item["path"] for item in cursor_projects.discover_projects(limit=100)
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
                project_roots=project_roots)
            if result.get("ok"):
                self.rules_cache.invalidate()
                result["archived_findings"] = (
                    self._archive_orphaned_findings(req["rule_id"]))
                self.incidents.clear(rule_id=req["rule_id"])
            return result
        if rtype == "stop_rule_everywhere":
            rule_id = req["rule_id"]
            result = rules_api.set_enabled(rule_id, False, None)
            for item in cursor_projects.discover_projects(limit=100):
                rules_api.set_enabled(
                    rule_id, False, item["path"], name=req.get("name"))
            self.rules_cache.invalidate()
            return result
        if rtype == "customize_for_project":
            result = rules_api.customize_for_project(
                req["rule_id"], req["project_root"])
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
                definition.get("source_hash", ""))
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
            elif result.get("ok") and not req.get("enabled"):
                self.incidents.clear(
                    project_root=project_root or None,
                    rule_id=req["rule_id"])
            return result
        if rtype == "set_project_monitoring":
            result = rules_api.set_project_enabled(
                req["project_root"], bool(req.get("enabled")))
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
