from __future__ import annotations

import threading
from pathlib import Path

from rules_as_programs import config, rules_api
from rules_as_programs.core import revisions
from rules_as_programs.core.rule import new_rule_id
from rules_as_programs.daemon import Daemon


class Runtime:
    available = True

    def __init__(self, fail_cases: bool = False):
        self.fail_cases = fail_cases
        self.compiles = 0
        self.compilers = []

    def program_id_for_spec(self, _spec, compiler=None):
        self.compiles += 1
        self.compilers.append(compiler)
        return "program"

    def warm(self, _program_id):
        return True

    def run(self, _program_id, text):
        if self.fail_cases:
            return "CRITICAL"
        return "WARNING" if "rsync -av src/" in text else "OK"


class RulesCache:
    def invalidate(self):
        return None

    def get(self, project_root):
        return rules_api.load_rules(project_root or None)


class Work:
    def submit(self, *_args, **_kwargs):
        return None


def _daemon(monkeypatch, tmp_path, projects, *, fail_cases=False):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(
        config, "global_rules_dir", lambda: tmp_path / "global-rules")
    monkeypatch.setattr(
        "rules_as_programs.daemon.cursor_projects.discover_projects",
        lambda limit=100: [
            {"path": str(path), "name": path.name} for path in projects
        ],
    )
    daemon = Daemon.__new__(Daemon)
    daemon.runtime = Runtime(fail_cases)
    daemon.rules_cache = RulesCache()
    daemon.work = Work()
    daemon._state_lock = threading.Lock()
    daemon._warmed = set()
    daemon._warm_state = {}
    daemon.known_projects = set(str(path) for path in projects)
    daemon._prepared_deployments = {}
    daemon._deployment_lock = threading.Lock()
    return daemon


def _prepare(daemon, rule_id, source, coverage, **extra):
    return daemon.prepare_rule_deployment({
        "rule_id": rule_id,
        "source": source,
        "project_root": extra.get("project_root", ""),
        "source_changed": extra.get("source_changed", True),
        "expected_active_hash": extra.get("expected_active_hash", ""),
        "coverage": coverage,
    })


def test_new_library_rule_deploys_to_all_current_and_future_projects(
    monkeypatch, tmp_path
):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [first, second])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Deploy everywhere")

    prepared = _prepare(
        daemon, rule_id, source,
        {"mode": "all", "selected_projects": []})
    committed = daemon.commit_rule_deployment(prepared["token"])

    assert committed["ok"], committed
    assert committed["coverage"]["mode"] == "all"
    assert rules_api.is_enabled(rule_id, str(first))
    assert rules_api.is_enabled(rule_id, str(tmp_path / "future-project"))
    info = rules_api.get_rule(rule_id, None)
    assert info["scope"] == "global"
    assert info["active_hash"] == revisions.hash_source(source)
    assert info["active"]["program_id"] == "program"


def test_new_rule_draft_no_longer_requires_a_project(monkeypatch, tmp_path):
    daemon = _daemon(monkeypatch, tmp_path, [])

    result = daemon.dispatch({
        "type": "new_rule_draft",
        "project_root": "",
        "template": "paw",
    })

    assert result["ok"]
    assert result["rule"]["scope"] == "global"
    assert result["rule"]["new_draft"]
    assert result["rule"]["deployment"]["coverage"]["mode"] == "selected"


def test_finalized_deployment_tests_and_compiles_same_compiler(
    monkeypatch, tmp_path
):
    daemon = _daemon(monkeypatch, tmp_path, [])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Finalized")

    prepared = daemon.prepare_rule_deployment({
        "rule_id": rule_id,
        "source": source,
        "source_changed": True,
        "compiler": "paw-ft-bs48",
        "coverage": {"mode": "selected", "selected_projects": []},
    })

    assert prepared["ok"]
    assert daemon.runtime.compilers
    assert set(daemon.runtime.compilers) == {"paw-ft-bs48"}


def test_undeployed_coverage_draft_survives_editor_reopen(
    monkeypatch, tmp_path
):
    project = tmp_path / "project"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Coverage draft")
    saved = rules_api.save_library_draft(
        rule_id, source, expected_absent=True)
    rules_api.save_deployment_coverage_draft(rule_id, {
        "mode": "selected",
        "selected_projects": [str(project)],
    })

    plan = daemon.deployment_plan(rule_id)

    assert saved["ok"]
    assert plan["coverage"]["selected_projects"] == []
    assert plan["draft_coverage"]["selected_projects"] == [str(project)]
    assert not plan["draft_coverage"]["confirmed"]


def test_selected_coverage_and_assignment_only_deploy_skip_recompile(
    monkeypatch, tmp_path
):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [first, second])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Selected projects")
    prepared = _prepare(
        daemon, rule_id, source,
        {"mode": "selected", "selected_projects": [str(first)]})
    first_commit = daemon.commit_rule_deployment(prepared["token"])
    compile_count = daemon.runtime.compiles

    prepared = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(second)]},
        source_changed=False,
        expected_active_hash=first_commit["active"]["source_hash"],
    )
    second_commit = daemon.commit_rule_deployment(prepared["token"])

    assert second_commit["ok"]
    assert daemon.runtime.compiles == compile_count
    assert not rules_api.is_enabled(rule_id, str(first))
    assert rules_api.is_enabled(rule_id, str(second))


def test_failed_prepare_does_not_publish_or_change_coverage(
    monkeypatch, tmp_path
):
    project = tmp_path / "project"
    project.mkdir()
    daemon = _daemon(
        monkeypatch, tmp_path, [project], fail_cases=True)
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Fail deployment")

    prepared = _prepare(
        daemon, rule_id, source,
        {"mode": "all", "selected_projects": []})

    assert not prepared["ok"]
    assert not (config.global_rules_dir() / rule_id / "rule.py").exists()


def test_project_definition_migrates_to_library_during_deploy(
    monkeypatch, tmp_path
):
    project = tmp_path / "project"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Move to library")
    saved = rules_api.save_rule(rule_id, source, "project", str(project))
    revisions.activate(rule_id, saved["path"], source)

    prepared = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        expected_active_hash=revisions.hash_source(source),
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(prepared["token"])

    assert committed["ok"], committed
    assert committed["migrated_to_library"]
    assert not Path(saved["path"]).exists()
    assert (config.global_rules_dir() / rule_id / "rule.py").exists()


def test_project_migration_conflict_keeps_both_sources_unchanged(
    monkeypatch, tmp_path
):
    project = tmp_path / "project"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    shared_source = rules_api.draft_rule_source(rule_id, "Library version")
    project_source = rules_api.draft_rule_source(rule_id, "Project version")
    shared = rules_api.save_rule(rule_id, shared_source, "global", None)
    project_saved = rules_api.save_rule(
        rule_id, project_source, "project", str(project))
    revisions.activate(rule_id, project_saved["path"], project_source)

    prepared = _prepare(
        daemon,
        rule_id,
        project_source,
        {"mode": "selected", "selected_projects": [str(project)]},
        expected_active_hash=revisions.hash_source(project_source),
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(prepared["token"])

    assert not committed["ok"]
    assert committed["conflict"]
    assert Path(shared["path"]).read_text() == shared["source"]
    assert Path(project_saved["path"]).read_text() == project_saved["source"]


def test_coverage_commit_failure_does_not_publish_or_enable_new_rule(
    monkeypatch, tmp_path
):
    project = tmp_path / "project"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Rollback deploy")
    prepared = _prepare(
        daemon, rule_id, source,
        {"mode": "all", "selected_projects": []})
    monkeypatch.setattr(
        rules_api, "set_rule_coverage",
        lambda *_args, **_kwargs: {"ok": False, "error": "coverage failed"},
    )

    committed = daemon.commit_rule_deployment(prepared["token"])

    assert not committed["ok"]
    assert not (config.global_rules_dir() / rule_id / "rule.py").exists()
    assert not rules_api.is_enabled(rule_id, str(tmp_path / "future"))


def test_commit_rejects_working_source_changed_after_prepare(
    monkeypatch, tmp_path
):
    project = tmp_path / "project"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Original")
    first = _prepare(
        daemon, rule_id, source,
        {"mode": "selected", "selected_projects": [str(project)]})
    deployed = daemon.commit_rule_deployment(first["token"])
    prepared = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        source_changed=False,
        expected_active_hash=deployed["active"]["source_hash"],
    )
    changed = rules_api.draft_rule_source(rule_id, "Changed elsewhere")
    current = rules_api.get_rule(rule_id, None)
    rules_api.save_library_draft(
        rule_id,
        changed,
        expected_source_hash=current["definition"]["source_hash"],
    )

    committed = daemon.commit_rule_deployment(prepared["token"])

    assert not committed["ok"]
    assert "working draft changed" in committed["error"]
    assert "Changed elsewhere" in Path(current["path"]).read_text()


def test_project_migration_rolls_back_when_source_removal_fails(
    monkeypatch, tmp_path
):
    project = tmp_path / "project"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Rollback migration")
    project_saved = rules_api.save_rule(
        rule_id, source, "project", str(project))
    revisions.activate(rule_id, project_saved["path"], source)
    prepared = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        expected_active_hash=revisions.hash_source(source),
        project_root=str(project),
    )
    original_delete = rules_api.delete_rule_definition

    def fail_project_delete(rule_id, scope, *args, **kwargs):
        if scope == "project":
            return {"ok": False, "error": "project source busy"}
        return original_delete(rule_id, scope, *args, **kwargs)

    monkeypatch.setattr(
        rules_api, "delete_rule_definition", fail_project_delete)
    committed = daemon.commit_rule_deployment(prepared["token"])

    assert not committed["ok"]
    assert Path(project_saved["path"]).exists()
    assert not (config.global_rules_dir() / rule_id / "rule.py").exists()
    assert rules_api.is_enabled(rule_id, str(project))


def test_project_migration_coverage_failure_restores_running_rule(
    monkeypatch, tmp_path
):
    project = tmp_path / "project"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Coverage rollback")
    project_saved = rules_api.save_rule(
        rule_id, source, "project", str(project))
    revisions.activate(rule_id, project_saved["path"], source)
    prepared = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        expected_active_hash=revisions.hash_source(source),
        project_root=str(project),
    )
    monkeypatch.setattr(
        rules_api, "set_rule_coverage",
        lambda *_args, **_kwargs: {"ok": False, "error": "coverage failed"},
    )

    committed = daemon.commit_rule_deployment(prepared["token"])

    assert not committed["ok"]
    assert Path(project_saved["path"]).exists()
    assert not (config.global_rules_dir() / rule_id / "rule.py").exists()
    assert rules_api.is_enabled(rule_id, str(project))
