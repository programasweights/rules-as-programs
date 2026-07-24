from __future__ import annotations

import json
from pathlib import Path

from rules_as_programs import config, rules_api
from rules_as_programs.core.rule import new_rule_id


def _setup(monkeypatch, tmp_path):
    monkeypatch.setenv("RAP_STATE_DIR", str(tmp_path / "state"))
    global_rules = tmp_path / "global-rules"
    monkeypatch.setattr(config, "global_rules_dir", lambda: global_rules)
    return global_rules


def _save(rule_id: str, scope: str, project: str | None, name: str = "Rule"):
    result = rules_api.save_rule(
        rule_id,
        rules_api.draft_rule_source(rule_id, name),
        scope,
        project,
    )
    assert result["ok"], result
    return result


def test_delete_requires_exact_scope_path_and_current_hash(monkeypatch, tmp_path):
    global_rules = _setup(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    rule_id = new_rule_id()
    _save(rule_id, "global", None)
    info = rules_api.get_rule(rule_id, None)
    definition = info["definition"]

    wrong_scope = rules_api.delete_rule_definition(
        rule_id,
        "project",
        str(project),
        definition["source_path"],
        definition["source_hash"],
    )
    assert not wrong_scope["ok"]
    source_path = global_rules / rule_id / "rule.py"
    assert source_path.exists()

    source_path.write_text(source_path.read_text() + "# changed\n")
    stale = rules_api.delete_rule_definition(
        rule_id,
        "global",
        None,
        definition["source_path"],
        definition["source_hash"],
    )
    assert not stale["ok"]
    assert "changed" in stale["error"]
    assert source_path.exists()


def test_project_override_removal_preserves_assignment_and_shared_fallback(
    monkeypatch, tmp_path
):
    _setup(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    rule_id = new_rule_id()
    _save(rule_id, "global", None, "Shared Rule")
    rules_api.set_enabled(rule_id, False, None)
    customized = rules_api.customize_for_project(rule_id, str(project))
    assert customized["ok"]
    rules_api.set_enabled(rule_id, True, str(project), "Shared Rule")
    before = json.loads(
        config.project_rules_config_path(project).read_text())
    assert before["rules"][rule_id]["enabled"] is True

    info = rules_api.get_rule(rule_id, str(project))
    definition = info["definition"]
    removed = rules_api.delete_rule_definition(
        rule_id,
        "project",
        str(project),
        definition["source_path"],
        definition["source_hash"],
        project_roots=[str(project)],
    )

    assert removed["ok"]
    assert removed["fallback"]["scope"] == "global"
    assert rules_api.is_enabled(rule_id, str(project))
    after = json.loads(config.project_rules_config_path(project).read_text())
    assert after["rules"][rule_id]["enabled"] is True


def test_deleting_definition_cleans_only_state_it_owns(monkeypatch, tmp_path):
    global_rules = _setup(monkeypatch, tmp_path)
    override_project = tmp_path / "override"
    assigned_project = tmp_path / "assigned"
    override_project.mkdir()
    assigned_project.mkdir()
    rule_id = new_rule_id()
    _save(rule_id, "global", None, "Shared Rule")
    assert rules_api.customize_for_project(
        rule_id, str(override_project))["ok"]
    rules_api.set_enabled(rule_id, False, None)
    rules_api.set_enabled(rule_id, True, str(assigned_project), "Shared Rule")
    rules_api.set_mute(rule_id, None, None)
    assert not rules_api.is_enabled(rule_id, str(override_project))
    info = rules_api.get_rule(rule_id, None)

    deleted = rules_api.delete_rule_definition(
        rule_id,
        "global",
        None,
        info["definition"]["source_path"],
        info["definition"]["source_hash"],
        project_roots=[str(override_project), str(assigned_project)],
    )

    assert deleted["ok"]
    assert str(override_project) in deleted["surviving_project_overrides"]
    assert not (global_rules / rule_id / "rule.py").exists()
    assert (
        config.project_rules_dir(override_project) / rule_id / "rule.py"
    ).exists()
    assert not rules_api.is_enabled(rule_id, str(override_project))
    override_summary = next(
        rule for rule in rules_api.list_rules(str(override_project))
        if rule["id"] == rule_id)
    assert not override_summary["enabled"]
    assert rules_api.is_muted(rule_id, str(override_project))
    assert rules_api.is_muted(rule_id, str(assigned_project))
    assert deleted["assignment_state_preserved"]
    assigned = json.loads(
        config.project_rules_config_path(assigned_project).read_text())
    assert assigned["rules"][rule_id]["enabled"] is True


def test_malformed_rule_can_be_deleted_by_exact_file_identity(
    monkeypatch, tmp_path
):
    _setup(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    rule_id = new_rule_id()
    source_path = config.project_rules_dir(project) / rule_id / "rule.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_text("this is not python !!!\n")
    summary = rules_api.summarize_rule_error(
        str(source_path), "project", "SyntaxError", str(project))

    deleted = rules_api.delete_rule_definition(
        rule_id,
        "project",
        str(project),
        summary["definition"]["source_path"],
        summary["definition"]["source_hash"],
        project_roots=[str(project)],
    )

    assert deleted["ok"]
    assert not source_path.exists()


def test_revert_keeps_project_source_when_shared_rule_is_invalid(
    monkeypatch, tmp_path
):
    global_rules = _setup(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    rule_id = new_rule_id()
    _save(rule_id, "project", str(project), "Project Rule")
    shared_path = global_rules / rule_id / "rule.py"
    shared_path.parent.mkdir(parents=True)
    shared_path.write_text("not valid python !!!\n")
    info = rules_api.get_rule(rule_id, str(project))

    reverted = rules_api.revert_to_shared(
        rule_id,
        str(project),
        info["definition"]["source_path"],
        info["definition"]["source_hash"],
    )

    assert not reverted["ok"]
    assert "valid shared version" in reverted["error"]
    assert Path(info["definition"]["source_path"]).exists()


def test_delete_rejects_source_file_with_multiple_rules(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    first_id = new_rule_id()
    second_id = "invalid"
    source_path = config.project_rules_dir(project) / first_id / "rule.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_text(
        "import rules_as_programs as rap\n\n"
        f"@rap.rule(id={first_id!r}, name='First', on=['message'])\n"
        "def first(ctx):\n"
        "    return None\n\n"
        f"@rap.rule(id={second_id!r}, name='Second', on=['message'])\n"
        "def second(ctx):\n"
        "    return None\n\n"
        "raise RuntimeError('module import failed')\n"
    )
    summary = rules_api.summarize_rule_error(
        str(source_path), "project", "multiple rules", str(project))

    deleted = rules_api.delete_rule_definition(
        first_id,
        "project",
        str(project),
        summary["definition"]["source_path"],
        summary["definition"]["source_hash"],
    )

    assert not deleted["ok"]
    assert "multiple rules" in deleted["error"]
    assert source_path.exists()


def test_non_utf8_broken_rule_can_be_deleted(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    rule_id = new_rule_id()
    source_path = config.project_rules_dir(project) / rule_id / "rule.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(b"\xff\xfe\x00broken")
    _rules, errors = rules_api.list_rule_library_with_errors([str(project)])
    summary = next(
        error for error in errors if error["source_path"] == str(source_path))

    deleted = rules_api.delete_rule_definition(
        rule_id,
        "project",
        str(project),
        summary["definition"]["source_path"],
        summary["definition"]["source_hash"],
    )

    assert deleted["ok"]
    assert not source_path.exists()


def test_crlf_rule_identity_matches_raw_file_bytes(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    rule_id = new_rule_id()
    source_path = config.project_rules_dir(project) / rule_id / "rule.py"
    source_path.parent.mkdir(parents=True)
    source = rules_api.draft_rule_source(rule_id, "CRLF Rule")
    source_path.write_bytes(source.replace("\n", "\r\n").encode("utf-8"))
    info = rules_api.get_rule(rule_id, str(project))

    deleted = rules_api.delete_rule_definition(
        rule_id,
        "project",
        str(project),
        info["definition"]["source_path"],
        info["definition"]["source_hash"],
    )

    assert deleted["ok"]
    assert not source_path.exists()


def test_pep263_encoded_rule_keeps_raw_definition_identity(
    monkeypatch, tmp_path
):
    _setup(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    rule_id = new_rule_id()
    source_path = config.project_rules_dir(project) / rule_id / "rule.py"
    source_path.parent.mkdir(parents=True)
    source = (
        "# -*- coding: latin-1 -*-\n"
        "from rules_as_programs import rule\n\n"
        f"@rule(id={rule_id!r}, name='Café', on=['message'])\n"
        "def check(ctx):\n"
        "    return None\n"
    ).encode("latin-1")
    source_path.write_bytes(source)
    info = rules_api.get_rule(rule_id, str(project))

    deleted = rules_api.delete_rule_definition(
        rule_id,
        "project",
        str(project),
        info["definition"]["source_path"],
        info["definition"]["source_hash"],
    )

    assert info["name"] == "Café"
    assert deleted["ok"]
    assert not source_path.exists()


def test_revert_rechecks_fallback_before_removing_project_source(
    monkeypatch, tmp_path
):
    _setup(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    rule_id = new_rule_id()
    _save(rule_id, "global", None, "Shared Rule")
    assert rules_api.customize_for_project(rule_id, str(project))["ok"]
    info = rules_api.get_rule(rule_id, str(project))
    shared_path = config.global_rules_dir() / rule_id / "rule.py"
    calls = {"count": 0}

    def changing_fallback(_rule_id):
        calls["count"] += 1
        return shared_path if calls["count"] == 1 else None

    monkeypatch.setattr(
        rules_api, "_usable_shared_definition", changing_fallback)
    reverted = rules_api.revert_to_shared(
        rule_id,
        str(project),
        info["definition"]["source_path"],
        info["definition"]["source_hash"],
    )

    assert not reverted["ok"]
    assert Path(info["definition"]["source_path"]).exists()


def test_malformed_project_assignment_config_does_not_partial_delete(
    monkeypatch, tmp_path
):
    _setup(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    rule_id = new_rule_id()
    saved = _save(rule_id, "project", str(project), "Project Rule")
    config_path = config.project_rules_config_path(project)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text('{"version": 1, "rules": []}\n')

    deleted = rules_api.delete_rule_definition(
        rule_id,
        "project",
        str(project),
        saved["definition"]["source_path"],
        saved["definition"]["source_hash"],
    )

    assert deleted["ok"]
    assert not Path(saved["definition"]["source_path"]).exists()
    assert json.loads(config_path.read_text())["rules"] == {}


def test_state_cleanup_failure_is_returned_as_warning(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    rule_id = new_rule_id()
    saved = _save(rule_id, "project", str(project), "Project Rule")
    rules_api.set_mute(rule_id, None, str(project))
    original_save = rules_api._save

    def fail_mute_save(path, data):
        if path == config.mutes_path():
            raise OSError("read-only state")
        return original_save(path, data)

    monkeypatch.setattr(rules_api, "_save", fail_mute_save)
    deleted = rules_api.delete_rule_definition(
        rule_id,
        "project",
        str(project),
        saved["definition"]["source_path"],
        saved["definition"]["source_hash"],
    )

    assert deleted["ok"]
    assert any("read-only state" in warning for warning in deleted["warnings"])


def test_multiple_rules_can_be_deleted_sequentially(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    first_id = new_rule_id()
    second_id = new_rule_id()
    _save(first_id, "global", None, "First Rule")
    _save(second_id, "global", None, "Second Rule")

    first = rules_api.get_rule(first_id, None)["definition"]
    first_result = rules_api.delete_rule_definition(
        first_id,
        "global",
        None,
        first["source_path"],
        first["source_hash"],
    )
    library, errors = rules_api.list_rule_library_with_errors([])
    second = next(rule for rule in library if rule["id"] == second_id)
    second_result = rules_api.delete_rule_definition(
        second_id,
        "global",
        None,
        second["definition"]["source_path"],
        second["definition"]["source_hash"],
    )

    assert first_result["ok"]
    assert not errors
    assert second_result["ok"]
