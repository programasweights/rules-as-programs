from __future__ import annotations

import json
import shutil

from rules_as_programs import config, rules_api
from rules_as_programs.core.rule import new_rule_id


def test_global_default_with_project_override(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    rule_id = new_rule_id()
    config.rule_state_path().write_text(json.dumps({
        "version": 2, "global": {rule_id: False}, "projects": {},
    }))
    project_a = tmp_path / "project-a"
    project_b = tmp_path / "project-b"
    project_a.mkdir()
    project_b.mkdir()

    assert not rules_api.is_enabled(rule_id, str(project_a))
    assert not rules_api.is_enabled(rule_id, str(project_b))

    result = rules_api.set_enabled(rule_id, True, str(project_a))
    assert result["ok"]
    assert rules_api.is_enabled(rule_id, str(project_a))
    assert not rules_api.is_enabled(rule_id, str(project_b))

    state = json.loads(config.rule_state_path().read_text())
    assert state["version"] == 2
    assert state["global"][rule_id] is False
    assert str(project_a) not in state["projects"]
    project_config = json.loads(
        config.project_rules_config_path(project_a).read_text())
    assert project_config["rules"][rule_id]["enabled"] is True


def test_hide_future_findings_is_project_scoped(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    rule_id = new_rule_id()
    rules_api.set_mute(rule_id, None, "/project/a")
    assert rules_api.is_muted(rule_id, "/project/a")
    assert not rules_api.is_muted(rule_id, "/project/b")

    rules_api.clear_mute(rule_id, "/project/a")
    assert not rules_api.is_muted(rule_id, "/project/a")


def test_project_can_override_global_hidden_findings(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    rule_id = new_rule_id()
    config.mutes_path().write_text(json.dumps({
        "version": 2, "global": {rule_id: None}, "projects": {},
    }))
    assert rules_api.is_muted(rule_id, "/project/a")
    rules_api.clear_mute(rule_id, "/project/a")
    assert not rules_api.is_muted(rule_id, "/project/a")
    assert rules_api.is_muted(rule_id, "/project/b")


def test_global_pause_is_not_a_mute(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path))
    rules_api.set_monitoring_paused(True)
    assert rules_api.monitoring_paused()
    assert not rules_api.is_muted(new_rule_id(), "/project")
    rules_api.set_monitoring_paused(False)
    assert not rules_api.monitoring_paused()


def test_live_syntax_check_does_not_execute_rule_source(tmp_path):
    marker = tmp_path / "executed"
    source = (
        "from rules_as_programs import rule\n"
        f"open({str(marker)!r}, 'w').write('bad')\n"
        "@rule(on=['message'])\n"
        "def check(ctx):\n"
        "    return None\n"
    )
    ok, error = rules_api.check_source_syntax(source)
    assert ok, error
    assert not marker.exists()


def test_project_assignments_are_shareable_and_resettable(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    rule_id = new_rule_id()
    project = tmp_path / "project"
    clone = tmp_path / "clone"
    project.mkdir()
    clone.mkdir()
    rules_api.set_enabled(rule_id, False, None)
    result = rules_api.set_enabled(
        rule_id, True, str(project), name="Shared Rule")
    assert result["ok"]
    assert rules_api.is_enabled(rule_id, str(project))
    config_path = config.project_rules_config_path(project)
    value = json.loads(config_path.read_text())
    assert value["rules"][rule_id]["name"] == "Shared Rule"

    clone_config = config.project_rules_config_path(clone)
    clone_config.parent.mkdir(parents=True)
    shutil.copy2(config_path, clone_config)
    assert rules_api.is_enabled(rule_id, str(clone))

    reset = rules_api.reset_project_assignments(str(clone))
    assert reset["ok"]
    assert not rules_api.is_enabled(rule_id, str(clone))
