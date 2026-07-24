import threading

from rules_as_programs.core.incidents import IncidentStore
from rules_as_programs.core.rule import LoadedRule
from rules_as_programs.daemon import Daemon


def test_transient_incident_requires_threshold_and_success_clears():
    store = IncidentStore()
    details = dict(
        project_root="/project",
        rule_id="rule",
        rule_name="Rule",
        summary="Rule check returned no valid decision",
        detail="empty output",
    )

    store.record("invalid_output", **details, threshold=2)
    assert store.active() == []
    store.record("invalid_output", **details, threshold=2)
    assert store.active()[0]["count"] == 2
    assert store.clear(project_root="/project", rule_id="rule") == 1
    assert store.active() == []


def test_same_global_rule_incident_deduplicates_across_projects():
    store = IncidentStore()
    for project in ("/one", "/two"):
        store.record(
            "warm_failure",
            project_root=project,
            rule_id="rule",
            rule_name="Shared Rule",
            summary="Shared Rule failed",
            detail="compile failed",
            threshold=1,
        )

    incidents = store.active()
    assert len(incidents) == 1
    assert incidents[0]["summary"] == "Shared Rule failing in 2 projects"
    assert set(incidents[0]["affected_projects"]) == {"/one", "/two"}


def test_daemon_runtime_incident_self_clears_after_success():
    daemon = Daemon.__new__(Daemon)
    daemon.incidents = IncidentStore()
    daemon._state_lock = threading.Lock()
    daemon._last_successful_audit = 0
    rule = LoadedRule(
        id="rule", title="Rule", severity="warn", on=[],
        fn=lambda _ctx: None)

    daemon._on_rule_error(
        rule, "/project",
        "invalid fuzzy severity ''; expected OK, INFO, WARNING, or CRITICAL")
    daemon._on_rule_error(
        rule, "/project",
        "invalid fuzzy severity ''; expected OK, INFO, WARNING, or CRITICAL")
    assert daemon.incidents.active()
    daemon._on_rule_success(rule, "/project")
    assert daemon.incidents.active() == []


def test_retry_keeps_incident_until_success_and_retries_all_projects():
    class Work:
        def __init__(self):
            self.projects = []

        def submit(self, _fn, project):
            self.projects.append(project)

    daemon = Daemon.__new__(Daemon)
    daemon.incidents = IncidentStore()
    daemon.work = Work()
    for project in ("/one", "/two"):
        daemon.incidents.record(
            "warm_failure",
            project_root=project,
            rule_id="rule",
            rule_name="Rule",
            summary="Rule failed",
            threshold=1,
        )

    result = daemon.dispatch({
        "type": "retry_health_issue",
        "project_root": "/one",
        "affected_projects": ["/one", "/two"],
        "rule_id": "rule",
        "code": "warm_failure",
    })

    assert result["ok"]
    assert daemon.incidents.active()
    assert daemon.work.projects == ["/one", "/two"]
