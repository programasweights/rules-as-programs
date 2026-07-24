from __future__ import annotations

import threading

from rules_as_programs import rules_api
from rules_as_programs.core import audit
from rules_as_programs.core.attention import AttentionStore
from rules_as_programs.core.engine import Engine, RuleContext
from rules_as_programs.core.events import Event, MESSAGE, SESSION_STOP
from rules_as_programs.core.ledger import Ledger
from rules_as_programs.core.rule import LoadedRule, new_rule_id
from rules_as_programs.core.store import Verdict, VerdictStore
from rules_as_programs.daemon import Daemon


class FakeRuntime:
    available = True

    def __init__(self, output=None, warm=True):
        self.output = output
        self.warm_result = warm

    def program_id_for_spec(self, _spec, _compiler=None):
        return "program"

    def warm(self, _program_id):
        return self.warm_result

    def run(self, _program_id, _text):
        return self.output


def test_orphaned_findings_archive_but_fallback_findings_remain(
    monkeypatch, tmp_path
):
    missing_project = str(tmp_path / "missing")
    fallback_project = str(tmp_path / "fallback")
    store = VerdictStore(tmp_path / "verdicts.db")
    common = dict(
        rule_id="rule",
        rule_title="Rule",
        severity="warn",
        message="violation",
        conversation_id="conversation",
    )
    store.record(Verdict(project_root=missing_project, **common))
    store.record(Verdict(project_root=fallback_project, **common))
    monkeypatch.setattr(
        rules_api,
        "get_rule",
        lambda _rule_id, project_root: (
            {
                "scope": "global",
                "definition": {"source_hash": "fallback"},
            }
            if project_root == fallback_project else None
        ),
    )
    daemon = Daemon.__new__(Daemon)
    daemon.store = store

    assert daemon._archive_orphaned_findings("rule") == 1
    assert missing_project not in store.by_project()
    assert fallback_project in store.by_project()
    history = store.history_grouped(missing_project)
    assert history[0]["review_reason"] == "rule_deleted"


def test_muted_rule_still_evaluates_and_logs_but_is_suppressed(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    project = tmp_path / "project"
    project.mkdir()
    ledger = Ledger("conversation", str(project))
    store = VerdictStore(tmp_path / "verdicts.db")
    rule_path = project / "rule.py"
    rule_path.write_text("# exact source at finding time\n")
    rule = LoadedRule(
        id="rule",
        title="Rule",
        severity="warn",
        on=[MESSAGE],
        fn=lambda ctx: (
            ctx.evidence(latest=[MESSAGE]),
            "violation",
        )[1],
        scope="project",
        source_path=str(rule_path),
    )
    muted = {"value": True}
    engine = Engine(
        FakeRuntime(),
        store,
        lambda _project: [rule],
        is_muted=lambda _rule, _project: muted["value"],
        is_enabled=lambda _rule, _project: True,
    )
    event = Event(
        kind=MESSAGE,
        conversation_id="conversation",
        project_root=str(project),
        payload={"text": "agent claim"},
    )
    ledger.append(event)
    verdicts = engine.on_event(event, ledger)
    assert verdicts[0].suppressed
    assert store.by_project() == {}
    detail = audit.read_finding(str(project), verdicts[0].id)
    assert detail["trigger_event_id"] == event.id
    assert detail["trace"][0]["latest"][0]["text"] == "agent claim"
    assert detail["rule_source"] == "# exact source at finding time\n"
    assert detail["rule_scope"] == "project"
    assert detail["rule_source_hash"]

    # Changing surfacing state changes the dedupe signature, so a later
    # occurrence can become actionable without changing the rule message.
    muted["value"] = False
    event2 = Event(
        kind=MESSAGE,
        conversation_id="conversation",
        project_root=str(project),
        payload={"text": "another claim"},
    )
    ledger.append(event2)
    engine.on_event(event2, ledger)
    assert store.by_project()[str(project)][0]["suppressed"] == 0


def test_empty_paw_output_never_passes_example():
    daemon = Daemon.__new__(Daemon)
    daemon.runtime = FakeRuntime(output=None)
    rule = LoadedRule(
        id="rule",
        title="Rule",
        severity="warn",
        on=[MESSAGE],
        fn=lambda _ctx: None,
        spec="Return ONLY one of: OK, BAD",
        examples=[("input", "OK")],
    )
    daemon._rule_from = lambda _rule_id, _project, _source: rule
    result = daemon.test_rule("rule", "/project")
    assert result["total"] == 1
    assert result["passed"] == 0
    assert result["results"][0]["ok"] is False


class _Rules:
    def __init__(self, rules):
        self._rules = rules

    def get(self, _project):
        return self._rules


def test_warm_state_tracks_ready_and_failed(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    deterministic_id = new_rule_id()
    paw_id = new_rule_id()
    deterministic = LoadedRule(
        id=deterministic_id,
        title="Python",
        severity="info",
        on=[MESSAGE],
        fn=lambda _ctx: None,
    )
    paw = LoadedRule(
        id=paw_id,
        title="PAW",
        severity="warn",
        on=[MESSAGE],
        fn=lambda _ctx: None,
        spec="spec",
    )
    daemon = Daemon.__new__(Daemon)
    daemon.runtime = FakeRuntime(warm=False)
    daemon.rules_cache = _Rules([deterministic, paw])
    daemon._state_lock = threading.Lock()
    daemon._warm_state = {}
    daemon._warm("/project")
    assert daemon._warm_state["/project"][deterministic_id]["status"] == "ready"
    assert daemon._warm_state["/project"][paw_id]["status"] == "failed"


def test_attention_rule_creates_separate_needs_reply_state(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    project = tmp_path / "project"
    project.mkdir()
    ledger = Ledger("conversation", str(project))
    ledger.append(Event(
        kind=MESSAGE,
        conversation_id="conversation",
        project_root=str(project),
        generation_id="generation",
        payload={"text": "Which database should I use?"},
    ))
    stop = Event(
        kind=SESSION_STOP,
        conversation_id="conversation",
        project_root=str(project),
        generation_id="generation",
        payload={"status": "completed"},
    )
    ledger.append(stop)
    detector = LoadedRule(
        id="gn3xtat6av4fy690",
        title="Needs reply",
        severity="info",
        on=[SESSION_STOP],
        inputs=[MESSAGE],
        channel="attention",
        fn=lambda ctx: (
            "Agent needs a reply"
            if ctx.paw("spec")(ctx.input()) == "REPLY_NEEDED" else None),
        spec="spec",
    )
    daemon = Daemon.__new__(Daemon)
    daemon.runtime = FakeRuntime(output="REPLY_NEEDED")
    daemon.attention = AttentionStore()
    daemon.rules_cache = _Rules([detector])
    daemon._evaluate_attention(stop, ledger)
    active = daemon.attention.active()
    assert len(active) == 1
    assert active[0]["project_root"] == str(project)
    assert active[0]["confidence"] == "inferred"


def test_managed_fuzzy_severity_mapping_and_invalid_output(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    project = tmp_path / "project"
    project.mkdir()
    ledger = Ledger("conversation", str(project))
    context = RuleContext(ledger, FakeRuntime())
    assert context.finding("OK", "Rule") is None
    assert context.finding("INFO", "Rule") == ("info", "Rule")
    assert context.finding("WARNING", "Rule") == ("warn", "Rule")
    assert context.finding("CRITICAL", "Rule") == ("critical", "Rule")

    errors = []
    store = VerdictStore(tmp_path / "verdicts.db")
    invalid = LoadedRule(
        id="rule",
        title="Rule",
        severity="warn",
        on=[MESSAGE],
        fn=lambda ctx: ctx.finding("HIGH", "Rule"),
    )
    engine = Engine(
        FakeRuntime(), store, lambda _project: [invalid],
        on_error=lambda rule, root, message: errors.append(message),
        is_enabled=lambda *_args: True,
    )
    event = Event(
        kind=MESSAGE, conversation_id="conversation",
        project_root=str(project), payload={"text": "claim"})
    ledger.append(event)
    assert engine.on_event(event, ledger) == []
    assert "expected OK, INFO, WARNING, or CRITICAL" in errors[0]


def test_active_rule_compiler_is_used_by_default_paw_calls(tmp_path):
    class TrackingRuntime(FakeRuntime):
        def __init__(self):
            super().__init__(output="WARNING")
            self.compilers = []

        def program_id_for_spec(self, _spec, compiler=None):
            self.compilers.append(compiler)
            return "program"

    runtime = TrackingRuntime()
    project = str(tmp_path)
    ledger = Ledger("conversation", project)
    event = Event(
        kind=MESSAGE,
        conversation_id="conversation",
        project_root=project,
        payload={"text": "claim"},
    )
    ledger.append(event)
    rule = LoadedRule(
        id=new_rule_id(),
        title="Finalized",
        severity="warn",
        on=[MESSAGE],
        inputs=[MESSAGE],
        fn=lambda ctx: ctx.finding(
            ctx.paw("spec")(ctx.input()), "finding"),
        spec="spec",
        compiler="paw-ft-bs48",
    )
    engine = Engine(
        runtime,
        VerdictStore(tmp_path / "verdicts.db"),
        lambda _project: [rule],
        is_enabled=lambda *_args: True,
    )

    assert engine.evaluate(rule, ledger) is not None
    assert runtime.compilers == ["paw-ft-bs48"]
