from __future__ import annotations

import json
import sqlite3

from rules_as_programs import config, scaffold
from rules_as_programs.adapters.codex import projects
from rules_as_programs.adapters.codex.adapter import (
    CodexAdapter,
    SUBSCRIBED_HOOKS,
    event_identity,
    normalize,
    remove_installed_hooks,
)
from rules_as_programs.core.rule import new_rule_id
from rules_as_programs import rules_api


def test_codex_hook_install_is_nested_async_and_idempotent(monkeypatch, tmp_path):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "home"))
    project = tmp_path / "project"
    project.mkdir()
    (project / ".git").mkdir()
    hooks_path = config.codex_hooks_path("project", project)
    hooks_path.parent.mkdir(parents=True)
    rap_command = '"$(git rev-parse --show-toplevel)/.codex/hooks/rap-hook.sh"'
    hooks_path.write_text(
        json.dumps(
            {
                "description": "keep me",
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "other-hook"}],
                        },
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": rap_command,
                                    "timeout": 30,
                                    "statusMessage": "Existing RAP hook",
                                }
                            ],
                        },
                    ],
                },
            }
        )
    )

    adapter = CodexAdapter()
    adapter.install("project", str(project))
    adapter.install("project", str(project))

    data = json.loads(hooks_path.read_text())
    assert data["description"] == "keep me"
    assert set(SUBSCRIBED_HOOKS) <= set(data["hooks"])
    for hook_name in SUBSCRIBED_HOOKS:
        rap_handlers = [
            handler
            for group in data["hooks"][hook_name]
            if isinstance(group, dict)
            for handler in group.get("hooks", [])
            if "rap-hook.sh" in str(handler.get("command", ""))
        ]
        assert len(rap_handlers) == 1
        assert rap_handlers[0]["type"] == "command"
        if hook_name == "SessionEnd":
            assert "async" not in rap_handlers[0]
            assert rap_handlers[0]["timeout"] == 1
        else:
            assert rap_handlers[0]["async"] is True
            assert rap_handlers[0]["timeout"] == 5
    pre_tool_rap = next(
        handler
        for group in data["hooks"]["PreToolUse"]
        for handler in group.get("hooks", [])
        if "rap-hook.sh" in str(handler.get("command", ""))
    )
    assert pre_tool_rap["statusMessage"] == "Existing RAP hook"
    assert data["hooks"]["PreToolUse"][0]["matcher"] == "Bash"
    wrapper = project / ".codex" / "hooks" / "rap-hook.sh"
    assert "rules_as_programs.adapters.codex.hook_client" in wrapper.read_text()
    assert "Cursor" not in wrapper.read_text()

    assert remove_installed_hooks(hooks_path)
    cleaned = json.loads(hooks_path.read_text())
    assert cleaned["hooks"] == {
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "other-hook"}],
            }
        ],
    }


def test_global_install_collapses_legacy_quoted_rap_handlers(monkeypatch, tmp_path):
    codex_home = tmp_path / "home"
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    hooks_path = config.codex_hooks_path("global")
    hooks_path.parent.mkdir(parents=True)
    wrapper = codex_home / "hooks" / "rap-hook.sh"
    legacy_command = repr(str(wrapper))
    hooks_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": legacy_command,
                                    "statusMessage": "Legacy RAP hook",
                                }
                            ]
                        },
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": str(wrapper),
                                    "async": True,
                                    "timeout": 5,
                                }
                            ]
                        },
                    ],
                },
            }
        )
    )

    CodexAdapter().install("global")

    data = json.loads(hooks_path.read_text())
    handlers = [
        handler
        for group in data["hooks"]["PreToolUse"]
        for handler in group.get("hooks", [])
        if "rap-hook.sh" in str(handler.get("command", ""))
    ]
    assert len(handlers) == 1
    assert handlers[0]["command"] == str(wrapper)
    assert handlers[0]["async"] is True
    assert handlers[0]["timeout"] == 5
    assert handlers[0]["statusMessage"] == "Legacy RAP hook"


def test_codex_event_identity_is_stable_across_duplicate_deliveries(tmp_path):
    raw = {
        "session_id": "session",
        "turn_id": "turn",
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
        "tool_name": "Bash",
        "tool_use_id": "tool-1",
        "tool_input": {"command": "pytest -q"},
    }
    first = normalize(raw)[0]
    second = normalize(dict(raw))[0]

    assert first.id != second.id
    assert event_identity(first) == event_identity(second)

    distinct = normalize({**raw, "tool_use_id": "tool-2"})[0]
    assert event_identity(first) != event_identity(distinct)


def test_codex_event_identity_keeps_stop_events_distinct(tmp_path):
    raw = {
        "session_id": "session",
        "turn_id": "turn",
        "hook_event_name": "Stop",
        "cwd": str(tmp_path),
        "last_assistant_message": "Done.",
    }
    message, checkpoint = normalize(raw)

    assert event_identity(message) != event_identity(checkpoint)


def test_project_discovery_reads_codex_state_database(monkeypatch, tmp_path):
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    database = codex_home / "state_5.sqlite"
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            CREATE TABLE projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE project_roots (
                project_id TEXT NOT NULL,
                position INTEGER NOT NULL,
                path TEXT NOT NULL
            );
        """)
        connection.executemany(
            "INSERT INTO projects VALUES (?, ?, ?)",
            [("one", "First", 1000), ("two", "Second", 2000)],
        )
        connection.executemany(
            "INSERT INTO project_roots VALUES (?, ?, ?)",
            [("one", 0, str(first)), ("two", 0, str(second))],
        )

    discovered = projects.discover_projects()
    assert [item["path"] for item in discovered] == [str(second), str(first)]
    assert [item["name"] for item in discovered] == ["Second", "First"]


def test_legacy_cursor_state_is_copied_without_overwriting_codex(monkeypatch, tmp_path):
    project = tmp_path / "project"
    legacy = project / ".cursor" / "rules-as-programs"
    target = project / ".codex" / "rules-as-programs"
    rule_id = new_rule_id()
    source = rules_api.generate_managed_fuzzy_source(
        rule_id,
        "Legacy response rule",
        "Return ONLY one of: OK, WARNING",
        trigger="Stop",
    ).replace("trigger='Stop'", "trigger='afterAgentResponse'")
    legacy_rule = legacy / "rules" / rule_id / "rule.py"
    legacy_rule.parent.mkdir(parents=True)
    legacy_rule.write_text(source)
    (legacy / "config.json").write_text('{"version": 1, "rules": {}}')
    target.mkdir(parents=True)
    (target / "config.json").write_text('{"newer": true}')
    monkeypatch.setattr(
        config,
        "legacy_rules_dir",
        lambda scope, project_root=None: tmp_path / "no-global-legacy",
    )

    notes = scaffold.migrate_legacy_cursor_state("project", str(project))

    migrated = (target / "rules" / rule_id / "rule.py").read_text()
    assert "trigger='Stop'" in migrated
    assert "afterAgentResponse" not in migrated
    assert json.loads((target / "config.json").read_text()) == {"newer": True}
    assert any("legacy" in note for note in notes)
