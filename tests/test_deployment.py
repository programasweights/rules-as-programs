from __future__ import annotations

import threading
from pathlib import Path

from rules_as_programs import config, rules_api
from rules_as_programs.core import revisions
from rules_as_programs.core.deployment_queue import (
    CANCELLABLE_DEPLOYMENT_STATUSES,
    DeploymentQueueStore,
)
from rules_as_programs.core.rule import new_rule_id
from rules_as_programs.core.validation_store import ValidationResultStore
from rules_as_programs.daemon import Daemon


class Runtime:
    available = True

    def __init__(self, fail_cases: bool = False):
        self.fail_cases = fail_cases
        self.compiles = 0
        self.compilers = []
        self.runs = 0
        self.cached_programs = {}

    def program_id_for_spec(self, _spec, compiler=None, **_kwargs):
        key = (_spec.strip(), compiler or "")
        if key in self.cached_programs:
            return self.cached_programs[key]
        self.compiles += 1
        self.compilers.append(compiler)
        self.cached_programs[key] = "program"
        return "program"

    def cached_program_id_for_spec(self, spec, compiler=None):
        return self.cached_programs.get((spec.strip(), compiler or ""), "")

    def warm(self, _program_id):
        return True

    def compiler_info(self, name=""):
        if name == "future-standard":
            name = ""
        if name:
            return {
                "name": name,
                "latest_snapshot": (
                    "finetune-snapshot"
                    if name == "paw-ft-bs48"
                    else f"{name}-snapshot"
                ),
                "runtime_id": "runtime",
                "compiler_kind": (
                    "finetune_lora" if "ft" in name else "mapper_lora"),
                "supports_local_sdk": True,
                "description": name,
            }
        return {
            "name": "future-standard",
            "latest_snapshot": "standard-snapshot",
            "runtime_id": "runtime",
            "compiler_kind": "mapper_lora",
            "supports_local_sdk": True,
            "description": "Future Standard",
            "default": True,
        }

    def compatible_finetune_compiler(self, _active_compiler=""):
        return {
            "name": "paw-ft-bs48",
            "latest_snapshot": "finetune-snapshot",
            "runtime_id": "runtime",
            "compiler_kind": "finetune_lora",
            "supports_local_sdk": True,
            "description": "Finetuned Standard",
        }

    def run(self, _program_id, text):
        self.runs += 1
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
        "rules_as_programs.daemon.codex_projects.discover_projects",
        lambda limit=100: [
            {"path": str(path), "name": path.name} for path in projects
        ],
    )
    daemon = Daemon.__new__(Daemon)
    daemon.runtime = Runtime(fail_cases)
    daemon.rules_cache = RulesCache()
    daemon.validation_results = ValidationResultStore(
        tmp_path / "validation-results.db")
    daemon.deployment_queue = DeploymentQueueStore(
        tmp_path / "deployment-queue.json")
    daemon.work = Work()
    daemon.optimization_work = Work()
    daemon._state_lock = threading.Lock()
    daemon._warmed = set()
    daemon._warm_state = {}
    daemon.known_projects = set(str(path) for path in projects)
    daemon._prepared_deployments = {}
    daemon._deployment_lock = threading.Lock()
    daemon._finetune_jobs = {}
    daemon._finetune_lock = threading.Lock()
    daemon._workflow_admission_lock = threading.Lock()
    daemon._queued_deployment_lock = threading.Lock()
    daemon._queued_deployments_running = set()
    daemon._queued_validation_lock = threading.Lock()
    daemon._queued_validations_running = set()
    return daemon


def _prepare(daemon, rule_id, source, coverage, **extra):
    return daemon.prepare_rule_deployment({
        "rule_id": rule_id,
        "source": source,
        "project_root": extra.get("project_root", ""),
        "source_changed": extra.get("source_changed", True),
        "expected_active_hash": extra.get("expected_active_hash", ""),
        "coverage": coverage,
        "warnings": extra.get("warnings", []),
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
    assert result["rule"]["deployment"]["coverage"]["mode"] == "all"
    assert result["rule"]["deployment"]["draft_coverage"]["confirmed"]

    project = tmp_path / "project"
    project.mkdir()
    project_result = daemon.dispatch({
        "type": "new_rule_draft",
        "project_root": str(project),
        "template": "paw",
        "coverage_mode": "selected",
    })
    coverage = project_result["rule"]["deployment"]["draft_coverage"]
    assert coverage["mode"] == "selected"
    assert coverage["selected_projects"] == [str(project)]
    assert coverage["confirmed"]


def test_legacy_activation_compiles_without_implicit_validation(
    monkeypatch, tmp_path
):
    project = tmp_path / "legacy-activation"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project], fail_cases=True)
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Legacy activation")
    saved = rules_api.save_library_draft(
        rule_id, source, expected_absent=True)
    assert saved["ok"]
    runs_before = daemon.runtime.runs

    result = daemon.dispatch({
        "type": "activate_rule",
        "rule_id": rule_id,
        "project_root": str(project),
    })

    assert result["ok"]
    assert daemon.runtime.runs == runs_before
    assert result["active"]["program_id"] == "program"


def test_rule_name_changes_do_not_change_behavior_identity(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Original name")
    ok, renamed, error = rules_api.patch_rule_identity(
        source, rule_id, "Renamed rule")
    assert ok, error
    assert revisions.hash_source(source) != revisions.hash_source(renamed)
    assert revisions.behavior_hash(source) == revisions.behavior_hash(renamed)

    source_path = tmp_path / "rule.py"
    source_path.write_text(source)
    revisions.activate(rule_id, source_path, source, program_id="program")
    source_path.write_text(renamed)
    status = revisions.working_status(rule_id, source_path, renamed)

    assert not status["draft_changes"]
    assert status["active_behavior_hash"] == status["working_behavior_hash"]
    changed_spec = renamed.replace(
        "Decide whether this input should be shown to the user.",
        "Decide whether this materially different input should be shown.",
    )
    assert revisions.behavior_hash(changed_spec) != (
        revisions.behavior_hash(renamed))


def test_compiler_artifacts_are_retained_for_atomic_rollback(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Artifact rollback")
    source_path = tmp_path / "rule.py"
    source_path.write_text(source)
    deployed = revisions.activate(
        rule_id,
        source_path,
        source,
        compiler="future-standard",
        compiler_snapshot="standard-snapshot",
        program_id="standard-program",
        compiler_mode=revisions.AUTOMATIC_COMPILER_MODE,
    )
    optimized = revisions.activate_artifact(
        rule_id,
        source_path,
        deployed["behavior_hash"],
        compiler="future-finetune",
        compiler_snapshot="finetune-snapshot",
        program_id="finetune-program",
        compiler_mode=revisions.AUTOMATIC_COMPILER_MODE,
    )

    assert optimized["compiler"] == "future-finetune"
    assert len(optimized["artifacts"]) == 2
    rolled_back = revisions.activate_artifact(
        rule_id,
        source_path,
        deployed["behavior_hash"],
        compiler="future-standard",
        compiler_snapshot="standard-snapshot",
        program_id="standard-program",
        compiler_mode=revisions.EXPLICIT_COMPILER_MODE,
    )

    assert rolled_back["compiler"] == "future-standard"
    assert rolled_back["compiler_mode"] == revisions.EXPLICIT_COMPILER_MODE
    assert len(rolled_back["artifacts"]) == 2


def test_finalized_deployment_tests_and_compiles_same_compiler(
    monkeypatch, tmp_path
):
    daemon = _daemon(monkeypatch, tmp_path, [])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Finalized")
    started = daemon.start_finetune(
        rule_id, "", "paw-ft-bs48", source, [])
    daemon._run_finetune(rule_id, started["job"]["id"])
    candidate = daemon.finetune_status(rule_id, "")["job"]

    prepared = daemon.prepare_rule_deployment({
        "rule_id": rule_id,
        "source": source,
        "source_changed": True,
        "compiler": "paw-ft-bs48",
        "compiler_snapshot": candidate["compiler_snapshot"],
        "program_id": candidate["program_id"],
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
        "compiler": "future-compact",
        "compiler_snapshot": "compact-snapshot",
    })

    plan = daemon.deployment_plan(rule_id)

    assert saved["ok"]
    assert plan["coverage"]["selected_projects"] == []
    assert plan["draft_coverage"]["selected_projects"] == [str(project)]
    assert not plan["draft_coverage"]["confirmed"]
    assert plan["draft_coverage"]["compiler"] == "future-compact"


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


def test_prepare_does_not_run_embedded_spec_examples(
    monkeypatch, tmp_path
):
    project = tmp_path / "project"
    project.mkdir()
    daemon = _daemon(
        monkeypatch, tmp_path, [project], fail_cases=True)
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Fail deployment")
    projection = rules_api.source_projection(source)
    ok, source, error = rules_api.patch_source_projection(
        source,
        trigger=projection["trigger"],
        function_source=projection["function_source"],
        spec=(
            "Surface the failing example.\n"
            "Return ONLY one of: OK, WARNING\n\n"
            "Input: failing input\n"
            "Output: WARNING"
        ),
    )
    assert ok, error

    runs_before = daemon.runtime.runs
    prepared = _prepare(
        daemon, rule_id, source,
        {"mode": "all", "selected_projects": []})

    assert prepared["ok"]
    assert daemon.runtime.runs == runs_before
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


def test_finetuned_build_requires_explicit_activation(
    monkeypatch, tmp_path
):
    project = tmp_path / "finetune-project"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Finetune explicitly")
    prepared = _prepare(
        daemon, rule_id, source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(prepared["token"])
    assert committed["ok"], committed
    assert committed["active"]["compiler"] == "future-standard"
    assert committed["active"]["compiler_snapshot"] == "standard-snapshot"

    started = daemon.start_finetune(
        rule_id, str(project), "future-ft-v2")
    assert started["ok"]
    job_id = started["job"]["id"]
    assert daemon.finetune_status(
        rule_id, str(project))["job"]["status"] == "building"
    assert (
        rules_api.get_rule(rule_id, str(project))["active"]["compiler"]
        == "future-standard"
    )

    daemon._run_finetune(rule_id, job_id)
    ready = daemon.finetune_status(rule_id, str(project))
    assert ready["job"]["status"] == "ready"
    assert ready["active"]["compiler"] == "future-standard"
    assert daemon.runtime.compilers[-1] == "future-ft-v2"

    activated = daemon.activate_finetune(rule_id, str(project))
    assert activated["ok"]
    assert activated["active"]["compiler"] == "future-ft-v2"
    assert activated["active"]["compiler_snapshot"] == (
        "future-ft-v2-snapshot")
    assert rules_api.get_rule(
        rule_id, str(project))["active"]["compiler"] == "future-ft-v2"
    compiles_before_validation = daemon.runtime.compiles
    validation = daemon.validate_rule_cases(
        rule_id,
        str(project),
        source,
        [{"id": "active", "input": "git push", "expected": "OK"}],
    )
    assert validation["target"]["compiler"] == "future-ft-v2"
    assert validation["target"]["compiler_snapshot"] == (
        "future-ft-v2-snapshot")
    assert daemon.runtime.compiles == compiles_before_validation
    queued = daemon.queue_validation({
        "validation_id": "pinned-snapshot-validation",
        "rule_id": rule_id,
        "project_root": str(project),
        "source": source,
        "compiler": "future-ft-v2",
        "compiler_snapshot": "future-ft-v2-snapshot",
        "program_id": activated["active"]["program_id"],
        "validation_cases": [{
            "id": "pinned",
            "input": "git push",
            "expected": "OK",
        }],
    })
    original_compiler_info = daemon.runtime.compiler_info

    def advanced_catalog(name=""):
        info = dict(original_compiler_info(name))
        if name == "future-ft-v2":
            info["latest_snapshot"] = "future-ft-v2-new-snapshot"
        return info

    daemon.runtime.compiler_info = advanced_catalog
    daemon._run_queued_validation(queued["queue"]["id"])
    pinned = daemon.validation_queue_status(
        rule_id, queued["queue"]["id"])["queue"]
    assert pinned["status"] == "succeeded"
    assert pinned["result"]["target"]["compiler_snapshot"] == (
        "future-ft-v2-snapshot")


def test_stale_finetuned_build_cannot_activate(monkeypatch, tmp_path):
    project = tmp_path / "stale-project"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Stale finetune")
    prepared = _prepare(
        daemon, rule_id, source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(prepared["token"])
    started = daemon.start_finetune(rule_id, str(project))
    daemon._run_finetune(rule_id, started["job"]["id"])

    source_path = committed["rule"]["definition"]["source_path"]
    changed = source.replace(
        "Decide whether this input should be shown to the user.",
        "Decide whether this changed behavior should be shown.",
    )
    revisions.activate(rule_id, source_path, changed)
    result = daemon.activate_finetune(rule_id, str(project))

    assert not result["ok"]
    assert result["stale"]


def test_deploying_renamed_revision_keeps_compatible_compiler_build(
    monkeypatch, tmp_path
):
    project = tmp_path / "changed-during-build"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Original")
    prepared = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(prepared["token"])
    started = daemon.start_finetune(rule_id, str(project))
    assert started["job"]["status"] == "building"

    changed = source.replace("Original", "Changed")
    replacement = _prepare(
        daemon,
        rule_id,
        changed,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
        expected_active_hash=committed["active"]["source_hash"],
    )
    deployed = daemon.commit_rule_deployment(replacement["token"])

    assert deployed["ok"]
    assert not deployed["compiler_build_discarded"]
    assert daemon.finetune_status(
        rule_id, str(project))["job"]["status"] == "building"


def test_draft_compiler_build_deploys_exact_draft_and_reuses_tests(
    monkeypatch, tmp_path
):
    project = tmp_path / "draft-compiler"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Draft compiler")
    initial = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(initial["token"])
    changed = source.replace(
        "Decide whether this input should be shown to the user.",
        "Decide whether this edited draft should be shown to the user.",
    )
    cases = [{"id": "safe", "input": "git push", "expected": "OK"}]
    started = daemon.start_finetune(
        rule_id,
        str(project),
        "future-ft-v2",
        changed,
        cases,
    )
    daemon._run_finetune(rule_id, started["job"]["id"])
    candidate = daemon.finetune_status(rule_id, str(project))["job"]
    tested = daemon.validate_rule_cases(
        rule_id,
        str(project),
        changed,
        cases,
        "future-ft-v2",
        candidate["compiler_snapshot"],
        candidate["program_id"],
    )
    assert tested["validation"]["passed"] == 1
    runs_after_test = daemon.runtime.runs

    prepared = daemon.prepare_rule_deployment({
        "rule_id": rule_id,
        "source": changed,
        "project_root": str(project),
        "source_changed": True,
        "expected_active_hash": committed["active"]["source_hash"],
        "compiler": "future-ft-v2",
        "compiler_snapshot": candidate["compiler_snapshot"],
        "program_id": candidate["program_id"],
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "validation_cases": cases,
        "validation_policy": "cached",
    })

    assert prepared["ok"], prepared
    assert prepared["validation"]["total"] == 0
    assert daemon.runtime.runs == runs_after_test
    deployed = daemon.commit_rule_deployment(prepared["token"])
    assert deployed["active"]["source_hash"] == revisions.hash_source(changed)
    assert deployed["active"]["compiler"] == "future-ft-v2"
    assert deployed["active"]["program_id"] == candidate["program_id"]


def test_deploy_when_ready_runs_in_background_and_persists_status(
    monkeypatch, tmp_path
):
    project = tmp_path / "queued-deployment"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Queued deployment")
    initial = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(initial["token"])
    changed = source.replace(
        "Decide whether this input should be shown to the user.",
        "Decide whether this queued draft should be shown to the user.",
    )
    cases = [{"id": "safe", "input": "git push", "expected": "OK"}]
    request = {
        "deployment_id": "queued-intent",
        "rule_id": rule_id,
        "project_root": str(project),
        "source": changed,
        "compiler": "future-ft-v2",
        "compiler_snapshot": "future-ft-v2-snapshot",
        "validation_cases": cases,
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "expected_active_hash": committed["active"]["source_hash"],
    }
    queued = daemon.queue_deployment(request)

    assert queued["ok"]
    queue_id = queued["queue"]["id"]
    duplicate = daemon.queue_deployment(request)
    conflicting = daemon.queue_deployment({
        **request,
        "coverage": {"mode": "all", "selected_projects": []},
    })
    assert duplicate["idempotent"]
    assert conflicting["conflict"]
    assert duplicate["queue"]["id"] == queue_id
    assert queued["queue"]["status"] == "building"
    assert DeploymentQueueStore(
        tmp_path / "deployment-queue.json"
    ).get(queue_id)["status"] == "building"
    reopened = daemon.dispatch({
        "type": "rule_get",
        "rule_id": rule_id,
        "project_root": str(project),
    })["rule"]
    assert reopened["source"] == changed
    assert reopened["deployment"]["draft_coverage"]["compiler"] == (
        "future-ft-v2")
    daemon.deployment_queue.update(queue_id, status="checking")
    reopened_checking = daemon.dispatch({
        "type": "rule_get",
        "rule_id": rule_id,
        "project_root": str(project),
    })["rule"]
    assert reopened_checking["source"] == changed
    assert reopened_checking["deployment"]["draft_coverage"][
        "selected_projects"
    ] == [str(project)]
    latest_cases = [{
        "id": "updated",
        "input": "rm -rf build",
        "expected": "WARNING",
    }]
    rules_api.save_validation_cases(
        reopened["definition"]["source_path"], latest_cases)

    daemon._run_queued_deployment(queue_id)
    finished = daemon.deployment_queue_status(rule_id)["queue"]

    assert finished["status"] == "succeeded"
    assert daemon.runtime.compilers[-1] == "future-ft-v2"
    assert finished["result"]["active"]["compiler"] == "future-ft-v2"
    assert finished["result"]["active"]["source_hash"] == (
        revisions.hash_source(changed))
    assert rules_api.validation_cases(rule_id, str(project)) == [
        {**latest_cases[0], "note": ""}]


def test_validation_and_deployment_share_build_without_gating(
    monkeypatch, tmp_path
):
    project = tmp_path / "shared-build"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project], fail_cases=True)
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Shared build")
    initial = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(initial["token"])
    changed = source.replace(
        "Decide whether this input should be shown to the user.",
        "Decide whether this shared compiler build should be shown.",
    )
    cases = [{"id": "fails", "input": "git push", "expected": "OK"}]
    validation_request = {
        "validation_id": "validation-intent",
        "rule_id": rule_id,
        "project_root": str(project),
        "source": changed,
        "compiler": "future-ft-v2",
        "compiler_snapshot": "future-ft-v2-snapshot",
        "validation_cases": cases,
    }
    validation = daemon.queue_validation(validation_request)
    duplicate_validation = daemon.queue_validation(validation_request)
    conflicting_validation = daemon.queue_validation({
        **validation_request,
        "validation_cases": [{
            "id": "different",
            "input": "rm -rf build",
            "expected": "WARNING",
        }],
    })
    deployment = daemon.queue_deployment({
        "deployment_id": "deployment-intent",
        "rule_id": rule_id,
        "project_root": str(project),
        "source": changed,
        "compiler": "future-ft-v2",
        "compiler_snapshot": "future-ft-v2-snapshot",
        "validation_cases": cases,
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "expected_active_hash": committed["active"]["source_hash"],
    })

    assert validation["queue"]["status"] == "building"
    assert duplicate_validation["idempotent"]
    assert conflicting_validation["conflict"]
    assert deployment["queue"]["status"] == "building"
    assert daemon.deployment_queue.active_for_rule(
        rule_id, kind="validation")["id"] == "validation-intent"
    compiles_before = daemon.runtime.compiles

    daemon._run_queued_validation("validation-intent")
    validation_status = daemon.validation_queue_status(
        rule_id, "validation-intent")["queue"]
    assert validation_status["status"] == "succeeded"
    assert not validation_status["result"]["validation"]["ok"]
    assert daemon.runtime.compiles == compiles_before + 1
    compiles_after_validation = daemon.runtime.compiles

    daemon._run_queued_deployment("deployment-intent")
    deployment_status = daemon.deployment_queue_status(
        rule_id, "deployment-intent")["queue"]
    assert deployment_status["status"] == "succeeded"
    assert daemon.runtime.compiles == compiles_after_validation
    assert deployment_status["result"]["active"]["compiler"] == "future-ft-v2"


def test_pending_validation_resumes_after_restart(monkeypatch, tmp_path):
    project = tmp_path / "restart-validation"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Restart validation")
    prepared = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    daemon.commit_rule_deployment(prepared["token"])
    queued = daemon.queue_validation({
        "validation_id": "restart-validation-intent",
        "rule_id": rule_id,
        "project_root": str(project),
        "source": source,
        "compiler": "future-ft-v2",
        "compiler_snapshot": "future-ft-v2-snapshot",
        "validation_cases": [{
            "id": "safe",
            "input": "git push",
            "expected": "OK",
        }],
    })
    assert queued["queue"]["status"] == "building"

    restarted = _daemon(monkeypatch, tmp_path, [project])
    pending = restarted.deployment_queue.pending(kind="validation")
    assert [item["id"] for item in pending] == [
        "restart-validation-intent"]

    restarted._run_queued_validation("restart-validation-intent")

    status = restarted.validation_queue_status(
        rule_id, "restart-validation-intent")["queue"]
    assert status["status"] == "succeeded"
    assert status["result"]["validation"]["ok"]


def test_stale_compiler_snapshot_is_rejected_before_queueing(
    monkeypatch, tmp_path
):
    project = tmp_path / "stale-compiler"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Stale compiler")
    prepared = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(prepared["token"])
    changed = source.replace("Stale compiler", "Stale compiler changed")
    cases = [{"id": "safe", "input": "git push", "expected": "OK"}]

    validation = daemon.queue_validation({
        "validation_id": "stale-validation",
        "rule_id": rule_id,
        "project_root": str(project),
        "source": changed,
        "compiler": "future-ft-v2",
        "compiler_snapshot": "superseded-snapshot",
        "validation_cases": cases,
    })
    deployment = daemon.queue_deployment({
        "deployment_id": "stale-deployment",
        "rule_id": rule_id,
        "project_root": str(project),
        "source": changed,
        "compiler": "future-ft-v2",
        "compiler_snapshot": "superseded-snapshot",
        "validation_cases": cases,
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "expected_active_hash": committed["active"]["source_hash"],
    })

    assert validation["compiler_catalog_stale"]
    assert deployment["compiler_catalog_stale"]
    assert daemon.deployment_queue.get("stale-validation") is None
    assert daemon.deployment_queue.get("stale-deployment") is None


def test_queued_deployment_ignores_failed_validation(
    monkeypatch, tmp_path
):
    project = tmp_path / "queued-validation-failure"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project], fail_cases=True)
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Queued failure")
    initial = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(initial["token"])
    changed = source.replace("Queued failure", "Queued failure changed")
    cases = [{"id": "must-pass", "input": "git push", "expected": "OK"}]
    started = daemon.start_finetune(
        rule_id, str(project), "future-ft-v2", changed, cases)
    queued = daemon.queue_deployment({
        "rule_id": rule_id,
        "project_root": str(project),
        "source": changed,
        "compiler": "future-ft-v2",
        "validation_cases": cases,
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "expected_active_hash": committed["active"]["source_hash"],
    })
    daemon._run_finetune(rule_id, started["job"]["id"])
    candidate = daemon.finetune_status(rule_id, str(project))["job"]
    tested = daemon.validate_rule_cases(
        rule_id,
        str(project),
        changed,
        cases,
        "future-ft-v2",
        candidate["compiler_snapshot"],
        candidate["program_id"],
    )
    assert tested["validation"]["passed"] == 0
    runs_after_test = daemon.runtime.runs
    daemon._run_queued_deployment(queued["queue"]["id"])

    status = daemon.deployment_queue_status(rule_id)["queue"]
    assert status["status"] == "succeeded"
    assert daemon.runtime.runs == runs_after_test
    assert status["result"]["active"]["behavior_hash"] == (
        revisions.behavior_hash(changed))
    assert status["result"]["active"]["compiler"] == "future-ft-v2"


def test_standard_deployment_uses_persistent_idempotent_queue(
    monkeypatch, tmp_path
):
    project = tmp_path / "queued-standard"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Queued standard")
    initial = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(initial["token"])
    compiles_before = daemon.runtime.compiles
    changed = source.replace(
        "Decide whether this input should be shown to the user.",
        "Decide whether this queued standard draft should be shown.",
    )
    queued = daemon.queue_deployment({
        "deployment_id": "standard-intent",
        "rule_id": rule_id,
        "project_root": str(project),
        "source": changed,
        "compiler": "future-standard",
        "compiler_snapshot": "standard-snapshot",
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "expected_active_hash": committed["active"]["source_hash"],
    })

    assert queued["queue"]["status"] in ("building", "checking")
    daemon._run_queued_deployment("standard-intent")
    finished = daemon.deployment_queue_status(
        rule_id, "standard-intent")["queue"]
    assert finished["status"] == "succeeded"
    assert daemon.runtime.compiles == compiles_before + 1
    assert finished["result"]["active"]["source_hash"] == (
        revisions.hash_source(changed))


def test_coverage_only_queue_applies_requested_projects(
    monkeypatch, tmp_path
):
    first = tmp_path / "coverage-first"
    second = tmp_path / "coverage-second"
    first.mkdir()
    second.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [first, second])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Coverage queue")
    initial = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(first)]},
        project_root=str(first),
    )
    committed = daemon.commit_rule_deployment(initial["token"])
    active = committed["active"]
    queued = daemon.queue_deployment({
        "deployment_id": "coverage-only",
        "rule_id": rule_id,
        "project_root": str(first),
        "source": source,
        "compiler": active["compiler"],
        "compiler_mode": active["compiler_mode"],
        "compiler_snapshot": active["compiler_snapshot"],
        "program_id": active["program_id"],
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(second)],
        },
        "expected_active_hash": active["source_hash"],
    })

    daemon._run_queued_deployment(queued["queue"]["id"])

    finished = daemon.deployment_queue_status(
        rule_id, "coverage-only")["queue"]
    assert finished["status"] == "succeeded"
    assert finished["result"]["coverage"]["selected_projects"] == [
        str(second)]
    assert not rules_api.is_enabled(rule_id, str(first))
    assert rules_api.is_enabled(rule_id, str(second))


def test_cancelling_building_deployment_cannot_resurrect_worker(
    monkeypatch, tmp_path
):
    project = tmp_path / "cancel-deployment"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    monkeypatch.setattr(
        daemon, "_schedule_queued_deployment", lambda *_args, **_kwargs: None)
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Cancel deployment")
    initial = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(initial["token"])
    changed = source.replace(
        "Decide whether this input should be shown to the user.",
        "Decide whether this cancelled draft should be shown.",
    )
    queued = daemon.queue_deployment({
        "deployment_id": "cancelled-deployment",
        "rule_id": rule_id,
        "project_root": str(project),
        "source": changed,
        "compiler": "future-ft-v2",
        "compiler_snapshot": "future-ft-v2-snapshot",
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "expected_active_hash": committed["active"]["source_hash"],
    })
    started = threading.Event()
    release = threading.Event()
    compile_program = daemon._compile_program_for_snapshot

    def blocked_compile(*args, **kwargs):
        started.set()
        assert release.wait(2)
        return compile_program(*args, **kwargs)

    monkeypatch.setattr(
        daemon, "_compile_program_for_snapshot", blocked_compile)
    worker = threading.Thread(
        target=daemon._run_queued_deployment,
        args=(queued["queue"]["id"],),
    )
    worker.start()
    assert started.wait(2)

    cancelled = daemon.cancel_queued_deployment(
        rule_id,
        "Draft changed.",
        queued["queue"]["id"],
    )
    release.set()
    worker.join(timeout=2)

    assert cancelled["ok"]
    assert not worker.is_alive()
    assert daemon.deployment_queue.get(
        queued["queue"]["id"])["status"] == "cancelled"
    current = rules_api.get_rule(rule_id, str(project))
    assert current["active"]["source_hash"] == committed["active"]["source_hash"]


def test_cancelling_building_validation_cannot_run_or_resurrect(
    monkeypatch, tmp_path
):
    project = tmp_path / "cancel-validation"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Cancel validation")
    queued = daemon.queue_validation({
        "validation_id": "cancelled-validation",
        "rule_id": rule_id,
        "project_root": str(project),
        "source": source,
        "compiler": "future-ft-v2",
        "compiler_snapshot": "future-ft-v2-snapshot",
        "validation_cases": [{
            "id": "safe",
            "input": "git status",
            "expected": "OK",
        }],
    })
    started = threading.Event()
    release = threading.Event()
    compile_program = daemon._compile_program_for_snapshot

    def blocked_compile(*args, **kwargs):
        started.set()
        assert release.wait(2)
        return compile_program(*args, **kwargs)

    monkeypatch.setattr(
        daemon, "_compile_program_for_snapshot", blocked_compile)
    worker = threading.Thread(
        target=daemon._run_queued_validation,
        args=(queued["queue"]["id"],),
    )
    worker.start()
    assert started.wait(2)

    cancelled = daemon.cancel_queued_validation(
        rule_id,
        "Cases changed.",
        queued["queue"]["id"],
    )
    release.set()
    worker.join(timeout=2)

    assert cancelled["ok"]
    assert not worker.is_alive()
    assert daemon.runtime.runs == 0
    assert daemon.deployment_queue.get(
        queued["queue"]["id"])["status"] == "cancelled"


def test_late_cancellation_is_scoped_to_original_intent(
    monkeypatch, tmp_path
):
    project = tmp_path / "intent-cancellation"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    monkeypatch.setattr(
        daemon, "_schedule_queued_deployment", lambda *_args, **_kwargs: None)
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Intent cancellation")
    first = daemon.queue_deployment({
        "deployment_id": "old-intent",
        "rule_id": rule_id,
        "project_root": str(project),
        "source": source,
        "compiler": "future-ft-v2",
        "compiler_snapshot": "future-ft-v2-snapshot",
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "expected_active_hash": "",
    })
    changed = source.replace("Intent cancellation", "New intent")
    second = daemon.queue_deployment({
        "deployment_id": "new-intent",
        "rule_id": rule_id,
        "project_root": str(project),
        "source": changed,
        "compiler": "future-ft-v2",
        "compiler_snapshot": "future-ft-v2-snapshot",
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "expected_active_hash": "",
    })

    late = daemon.cancel_queued_deployment(
        rule_id, "Late callback.", first["queue"]["id"])

    assert not late["ok"]
    assert daemon.deployment_queue.get(
        second["queue"]["id"])["status"] == "building"


def test_compile_rejects_snapshot_change_during_build(
    monkeypatch, tmp_path
):
    daemon = _daemon(monkeypatch, tmp_path, [])
    snapshots = iter(("snapshot-a", "snapshot-b"))
    monkeypatch.setattr(daemon.runtime, "compiler_info", lambda _name="": {
        "name": "moving-compiler",
        "latest_snapshot": next(snapshots),
        "compiler_kind": "mapper_lora",
    })

    result = daemon._compile_program_for_snapshot(
        "Return OK.",
        "moving-compiler",
        "snapshot-a",
        timeout=None,
    )

    assert not result["ok"]
    assert result["compiler_catalog_stale"]


def test_queued_deployment_requires_successful_local_warmup(
    monkeypatch, tmp_path
):
    project = tmp_path / "warmup-gate"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Warmup gate")
    initial = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(initial["token"])
    changed = source.replace(
        "Decide whether this input should be shown to the user.",
        "Decide whether this warmup-gated input should be shown.",
    )
    queued = daemon.queue_deployment({
        "deployment_id": "warmup-gated",
        "rule_id": rule_id,
        "project_root": str(project),
        "source": changed,
        "compiler": "future-standard",
        "compiler_snapshot": "standard-snapshot",
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "expected_active_hash": committed["active"]["source_hash"],
    })
    monkeypatch.setattr(daemon.runtime, "warm", lambda _program_id: False)

    daemon._run_queued_deployment(queued["queue"]["id"])

    finished = daemon.deployment_queue.get(queued["queue"]["id"])
    assert finished["status"] == "failed"
    assert finished["phase"] == "Warmup failed"
    active = rules_api.get_rule(rule_id, str(project))["active"]
    assert active["source_hash"] == committed["active"]["source_hash"]


def test_finetune_and_direct_validation_reject_stale_snapshots(
    monkeypatch, tmp_path
):
    project = tmp_path / "snapshot-gates"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Snapshot gates")
    started = daemon.start_finetune(
        rule_id, str(project), "future-ft-v2", source, [])
    original_info = daemon.runtime.compiler_info

    def changed_info(name=""):
        value = dict(original_info(name))
        if name == "future-ft-v2":
            value["latest_snapshot"] = "newer-snapshot"
        return value

    monkeypatch.setattr(daemon.runtime, "compiler_info", changed_info)
    compiles_before = daemon.runtime.compiles
    daemon._run_finetune(rule_id, started["job"]["id"])

    job = daemon.finetune_status(rule_id, str(project))["job"]
    assert job["status"] == "failed"
    assert daemon.runtime.compiles == compiles_before

    validation = daemon.validate_rule_cases(
        rule_id,
        str(project),
        source,
        [{"id": "case", "input": "git status", "expected": "OK"}],
        "future-ft-v2",
        "future-ft-v2-snapshot",
    )

    assert not validation["ok"]
    assert validation["compiler_catalog_stale"]
    assert daemon.runtime.runs == 0


def test_concurrent_validation_additions_are_serialized(
    monkeypatch, tmp_path
):
    project = tmp_path / "validation-additions"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Concurrent cases")
    prepared = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(prepared["token"])
    source_path = committed["rule"]["definition"]["source_path"]
    original_load = rules_api.validation_cases_for_path
    active_readers = 0
    max_readers = 0
    readers_lock = threading.Lock()
    start = threading.Event()

    def slow_load(path):
        nonlocal active_readers, max_readers
        with readers_lock:
            active_readers += 1
            max_readers = max(max_readers, active_readers)
        try:
            threading.Event().wait(0.03)
            return original_load(path)
        finally:
            with readers_lock:
                active_readers -= 1

    monkeypatch.setattr(rules_api, "validation_cases_for_path", slow_load)
    results = []

    def add(input_text):
        assert start.wait(2)
        results.append(rules_api.add_validation_case(
            rule_id, str(project), input_text, "OK"))

    threads = [
        threading.Thread(target=add, args=("first",)),
        threading.Thread(target=add, args=("second",)),
    ]
    for thread in threads:
        thread.start()
    start.set()
    for thread in threads:
        thread.join(timeout=2)

    assert all(result["ok"] for result in results)
    assert max_readers == 1
    assert {
        case["input"]
        for case in rules_api.validation_cases_for_path(source_path)
    } == {"first", "second"}


def test_validation_case_save_cannot_be_lost_during_commit(
    monkeypatch, tmp_path
):
    project = tmp_path / "validation-commit"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Validation commit")
    initial = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(initial["token"])
    source_path = committed["rule"]["definition"]["source_path"]
    old_cases = [{
        "id": "old",
        "input": "git status",
        "expected": "OK",
    }]
    newer_cases = [{
        "id": "new",
        "input": "rm -rf build",
        "expected": "WARNING",
    }]
    rules_api.save_validation_cases(source_path, old_cases)
    prepared = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        source_changed=False,
        expected_active_hash=committed["active"]["source_hash"],
        project_root=str(project),
    )
    entered_commit = threading.Event()
    release_commit = threading.Event()
    original_save = rules_api.save_library_draft

    def blocked_save(*args, **kwargs):
        entered_commit.set()
        assert release_commit.wait(2)
        return original_save(*args, **kwargs)

    monkeypatch.setattr(rules_api, "save_library_draft", blocked_save)
    commit_result = {}
    save_result = {}

    def commit():
        commit_result.update(
            daemon.commit_rule_deployment(prepared["token"]))

    def save():
        save_result.update(daemon.dispatch({
            "type": "save_validation_cases",
            "rule_id": rule_id,
            "project_root": str(project),
            "validation_cases": newer_cases,
        }))

    commit_thread = threading.Thread(target=commit)
    commit_thread.start()
    assert entered_commit.wait(2)
    save_thread = threading.Thread(target=save)
    save_thread.start()
    release_commit.set()
    commit_thread.join(timeout=2)
    save_thread.join(timeout=2)

    assert commit_result["ok"]
    assert save_result["ok"]
    assert rules_api.validation_cases(rule_id, str(project)) == [{
        **newer_cases[0],
        "note": "",
    }]


def test_automatic_deploy_promotes_background_finetune_without_tests(
    monkeypatch, tmp_path
):
    project = tmp_path / "automatic-optimization"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Automatic optimization")
    prepared = daemon.prepare_rule_deployment({
        "rule_id": rule_id,
        "source": source,
        "project_root": str(project),
        "source_changed": True,
        "expected_active_hash": "",
        "compiler_mode": revisions.AUTOMATIC_COMPILER_MODE,
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "validation_cases": [{
            "id": "never-run",
            "input": "git push",
            "expected": "WARNING",
        }],
    })

    assert prepared["ok"]
    assert prepared["compiler_mode"] == revisions.AUTOMATIC_COMPILER_MODE
    committed = daemon.commit_rule_deployment(prepared["token"])
    optimization = committed["optimization"]
    assert committed["active"]["compiler"] == "future-standard"
    assert committed["active"]["compiler_mode"] == (
        revisions.AUTOMATIC_COMPILER_MODE)
    assert optimization["status"] == "waiting_for_build"
    assert daemon.runtime.runs == 0
    duplicate = daemon._queue_automatic_optimization(
        rule_id=rule_id,
        project_root=str(project),
        source_path=committed["active"]["source_path"],
        source=source,
        active=committed["active"],
    )
    assert duplicate["id"] == optimization["id"]
    assert len(daemon.deployment_queue.pending(kind="optimization")) == 1

    daemon._run_optimization(optimization["id"])

    active = rules_api.get_rule(rule_id, str(project))["active"]
    assert active["compiler"] == "paw-ft-bs48"
    assert active["compiler_mode"] == revisions.AUTOMATIC_COMPILER_MODE
    assert {
        artifact["compiler"]
        for artifact in active["artifacts"].values()
    } == {"future-standard", "paw-ft-bs48"}
    assert daemon.runtime.runs == 0
    finished = daemon.deployment_queue.latest_for_rule(
        rule_id, kind="optimization")
    assert finished["status"] == "succeeded"


def test_cancelled_optimization_cannot_promote_after_build(
    monkeypatch, tmp_path
):
    project = tmp_path / "cancel-optimization"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Cancel optimization")
    prepared = daemon.prepare_rule_deployment({
        "rule_id": rule_id,
        "source": source,
        "project_root": str(project),
        "source_changed": True,
        "expected_active_hash": "",
        "compiler_mode": revisions.AUTOMATIC_COMPILER_MODE,
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
    })
    committed = daemon.commit_rule_deployment(prepared["token"])
    queue_id = committed["optimization"]["id"]
    base_compiler = committed["active"]["compiler"]
    started = threading.Event()
    release = threading.Event()
    compile_program = daemon._compile_program_for_snapshot

    def blocked_compile(*args, **kwargs):
        started.set()
        assert release.wait(2)
        return compile_program(*args, **kwargs)

    monkeypatch.setattr(
        daemon, "_compile_program_for_snapshot", blocked_compile)
    worker = threading.Thread(
        target=daemon._run_optimization, args=(queue_id,))
    worker.start()
    assert started.wait(2)
    cancelled = daemon.deployment_queue.cancel(
        queue_id,
        "Automatic optimization disabled.",
        expected_statuses=CANCELLABLE_DEPLOYMENT_STATUSES,
    )
    release.set()
    worker.join(timeout=2)

    assert cancelled["status"] == "cancelled"
    assert not worker.is_alive()
    active = rules_api.get_rule(rule_id, str(project))["active"]
    assert active["compiler"] == base_compiler
    assert daemon.deployment_queue.get(queue_id)["status"] == "cancelled"


def test_explicit_compiler_deploy_does_not_schedule_optimization(
    monkeypatch, tmp_path
):
    project = tmp_path / "explicit-compiler"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Explicit compiler")
    prepared = daemon.prepare_rule_deployment({
        "rule_id": rule_id,
        "source": source,
        "project_root": str(project),
        "source_changed": True,
        "expected_active_hash": "",
        "compiler": "future-standard",
        "compiler_mode": revisions.EXPLICIT_COMPILER_MODE,
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
    })

    committed = daemon.commit_rule_deployment(prepared["token"])

    assert committed["active"]["compiler_mode"] == (
        revisions.EXPLICIT_COMPILER_MODE)
    assert committed["optimization"] == {}
    assert daemon.deployment_queue.latest_for_rule(
        rule_id, kind="optimization") is None


def test_pending_automatic_optimization_resumes_after_restart(
    monkeypatch, tmp_path
):
    project = tmp_path / "restart-optimization"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Restart optimization")
    prepared = daemon.prepare_rule_deployment({
        "rule_id": rule_id,
        "source": source,
        "project_root": str(project),
        "source_changed": True,
        "expected_active_hash": "",
        "compiler_mode": revisions.AUTOMATIC_COMPILER_MODE,
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
    })
    committed = daemon.commit_rule_deployment(prepared["token"])
    queue_id = committed["optimization"]["id"]

    restarted = _daemon(monkeypatch, tmp_path, [project])
    pending = restarted.deployment_queue.pending(kind="optimization")
    assert [item["id"] for item in pending] == [queue_id]

    restarted._run_optimization(queue_id)

    active = revisions.active_info(
        rule_id, committed["rule"]["definition"]["source_path"])
    assert active["compiler"] == "paw-ft-bs48"
    assert restarted.deployment_queue.get(queue_id)["status"] == "succeeded"


def test_new_explicit_deploy_cancels_stale_automatic_promotion(
    monkeypatch, tmp_path
):
    project = tmp_path / "stale-optimization"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Stale optimization")
    automatic = daemon.prepare_rule_deployment({
        "rule_id": rule_id,
        "source": source,
        "project_root": str(project),
        "source_changed": True,
        "expected_active_hash": "",
        "compiler_mode": revisions.AUTOMATIC_COMPILER_MODE,
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
    })
    first = daemon.commit_rule_deployment(automatic["token"])
    stale_queue_id = first["optimization"]["id"]
    changed = source.replace(
        "Decide whether this input should be shown to the user.",
        "Decide whether this newer revision should be shown to the user.",
    )
    explicit = daemon.prepare_rule_deployment({
        "rule_id": rule_id,
        "source": changed,
        "project_root": str(project),
        "source_changed": True,
        "expected_active_hash": first["active"]["source_hash"],
        "compiler": "future-standard",
        "compiler_mode": revisions.EXPLICIT_COMPILER_MODE,
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
    })
    second = daemon.commit_rule_deployment(explicit["token"])

    assert daemon.deployment_queue.get(stale_queue_id)["status"] == "cancelled"
    daemon._run_optimization(stale_queue_id)
    active = revisions.active_info(
        rule_id, second["rule"]["definition"]["source_path"])
    assert active["behavior_hash"] == revisions.behavior_hash(changed)
    assert active["compiler_mode"] == revisions.EXPLICIT_COMPILER_MODE
    assert active["compiler"] == "future-standard"


def test_deploy_anyway_warning_is_stored_with_revision(
    monkeypatch, tmp_path
):
    project = tmp_path / "warning-project"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Warning record")
    warning = (
        "Include OK and at least one of INFO, WARNING, or CRITICAL "
        "so PAW knows when to create a finding.")
    prepared = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
        warnings=[warning],
    )

    committed = daemon.commit_rule_deployment(prepared["token"])

    assert committed["warnings"] == [warning]
    assert committed["active"]["warnings"] == [warning]


def test_validation_cases_persist_without_running_during_deploy(
    monkeypatch, tmp_path
):
    project = tmp_path / "validation-project"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Validate behavior")
    cases = [
        {"id": "ok", "input": "git push", "expected": "OK"},
        {
            "id": "warn",
            "input": "rsync -av src/ host:/app",
            "expected": "WARNING",
        },
    ]
    runs_before = daemon.runtime.runs
    prepared = daemon.prepare_rule_deployment({
        "rule_id": rule_id,
        "source": source,
        "project_root": str(project),
        "source_changed": True,
        "expected_active_hash": "",
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "validation_cases": cases,
    })

    assert prepared["ok"], prepared
    assert prepared["validation"]["total"] == 0
    assert daemon.runtime.runs == runs_before
    committed = daemon.commit_rule_deployment(prepared["token"])
    assert committed["validation"]["total"] == 0
    assert daemon.runtime.runs == runs_before
    daemon.validation_results = ValidationResultStore(
        tmp_path / "validation-results.db")
    cached = daemon.cached_validation_results(
        rule_id, str(project), source, cases)
    assert cached["validation"]["matched"] == 0
    assert cached["target"]["compiler"] == "future-standard"
    source_path = committed["rule"]["definition"]["source_path"]
    assert rules_api.validation_cases_for_path(source_path) == [
        {"id": "ok", "input": "git push", "expected": "OK", "note": ""},
        {
            "id": "warn",
            "input": "rsync -av src/ host:/app",
            "expected": "WARNING",
            "note": "",
        },
    ]


def test_failed_validation_does_not_gate_deployment(
    monkeypatch, tmp_path
):
    project = tmp_path / "failed-validation"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Validation failure")
    request = {
        "rule_id": rule_id,
        "source": source,
        "project_root": str(project),
        "source_changed": True,
        "expected_active_hash": "",
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "validation_cases": [{
            "id": "wrong",
            "input": "git push",
            "expected": "WARNING",
        }],
    }

    tested = daemon.validate_rule_cases(
        rule_id,
        str(project),
        source,
        request["validation_cases"],
    )
    assert tested["validation"]["passed"] == 0
    runs_after_test = daemon.runtime.runs
    prepared = daemon.prepare_rule_deployment(request)
    assert prepared["ok"]
    assert prepared["validation"]["total"] == 0
    assert daemon.runtime.runs == runs_after_test


def test_deploy_never_runs_validation_for_any_policy(
    monkeypatch, tmp_path
):
    project = tmp_path / "explicit-validation"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project], fail_cases=True)
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Explicit validation")
    cases = [{"id": "case", "input": "git push", "expected": "OK"}]
    request = {
        "rule_id": rule_id,
        "source": source,
        "project_root": str(project),
        "source_changed": True,
        "expected_active_hash": "",
        "coverage": {
            "mode": "selected",
            "selected_projects": [str(project)],
        },
        "validation_cases": cases,
    }

    runs_before = daemon.runtime.runs
    for policy in ("skip", "cached", "allow_failed", "run"):
        prepared = daemon.prepare_rule_deployment({
            **request, "validation_policy": policy})
        assert prepared["ok"]
        assert prepared["validation"]["total"] == 0
        assert daemon.runtime.runs == runs_before


def test_finetuned_build_does_not_run_validation_cases(
    monkeypatch, tmp_path
):
    project = tmp_path / "finetune-validation"
    project.mkdir()
    daemon = _daemon(monkeypatch, tmp_path, [project])
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Finetune validation")
    prepared = _prepare(
        daemon,
        rule_id,
        source,
        {"mode": "selected", "selected_projects": [str(project)]},
        project_root=str(project),
    )
    committed = daemon.commit_rule_deployment(prepared["token"])
    source_path = committed["rule"]["definition"]["source_path"]
    rules_api.save_validation_cases(source_path, [{
        "id": "wrong",
        "input": "git push",
        "expected": "WARNING",
    }])
    started = daemon.start_finetune(rule_id, str(project))
    daemon._run_finetune(rule_id, started["job"]["id"])
    status = daemon.finetune_status(rule_id, str(project))
    assert status["job"]["validation"]["total"] == 0
    assert "only when requested" in status["job"]["validation"]["note"]

    activated = daemon.activate_finetune(rule_id, str(project))
    assert activated["ok"]


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
