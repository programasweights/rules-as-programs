from __future__ import annotations

import hashlib
import json
import os
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.eacl2027 import run_public_codex_field_replay as replay


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_rule(root: Path, rule_id: str, trigger: str = "PreToolUse") -> Path:
    path = root / "rules" / rule_id / "rule.py"
    path.parent.mkdir(parents=True)
    path.write_text(
        "from rules_as_programs import rule\n\n"
        f"@rule(id={rule_id!r}, name='Replay rule', trigger={trigger!r}, "
        "spec='Return ONLY one of: OK, WARNING')\n"
        "def replay_rule(ctx):\n"
        "    return ctx.result('OK')\n",
        encoding="utf-8",
    )
    return path


def _settings() -> dict:
    return {
        "version": "codex-cli 0.test",
        "executable_sha256": "b" * 64,
        "model": "gpt-test-pinned",
        "reasoning_effort": "high",
        "sandbox": "workspace-write",
        "approval_policy": "never",
        "network_access": False,
        "web_search": "disabled",
        "ignore_rules": True,
        "shell_environment_inherit": "core",
        "service_tier": "default",
        "ephemeral": True,
        "strict_config": True,
        "isolated_codex_home": True,
        "timeout_seconds": 120,
    }


def _session(
    root: Path,
    *,
    rule_id: str = "0000000000000001",
    trigger: str = "PreToolUse",
    session_id: str = "session-1",
    task_id: str = "task-1",
    condition: str = "source instruction present",
    repository_commit: str = "a" * 40,
    rule_path: Path | None = None,
    prompt_path: Path | None = None,
) -> dict:
    rule_path = rule_path or _write_rule(root, rule_id, trigger)
    if prompt_path is None:
        prompt_path = root / "tasks" / f"{task_id}-{condition[-7:]}.txt"
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(f"Complete {task_id}.\n", encoding="utf-8")
    return {
        "session_id": session_id,
        "rule_id": rule_id,
        "trigger": trigger,
        "input_pointer": replay.SUPPORTED_FIELDS[trigger],
        "rule_source_path": str(rule_path.relative_to(root)),
        "rule_source_sha256": replay._sha256_file(rule_path),
        "rule_revision_id": f"revision-{rule_id}",
        "rule_behavior_sha256": replay.behavior_hash(
            rule_path.read_text(encoding="utf-8")
        ),
        "repository_url": "https://github.com/example/public-repo.git",
        "repository_commit": repository_commit,
        "task_id": task_id,
        "task_prompt_path": str(prompt_path.relative_to(root)),
        "task_prompt_sha256": replay._sha256_file(prompt_path),
        "instruction_condition": condition,
    }


def _write_plan(
    root: Path,
    sessions: list[dict],
    *,
    study_mode: str = replay.PILOT,
) -> Path:
    settings = _settings()
    if study_mode == replay.FORMAL:
        settings["ignore_rules"] = False
    path = root / "plan.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "protocol_version": replay.PROTOCOL_VERSION,
                "protocol_sha256": replay.PROTOCOL_SHA256,
                "study": replay.STUDY_NAME,
                "study_mode": study_mode,
                "codex": settings,
                "sessions": sessions,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _validated_pilot(
    tmp_path: Path,
    *,
    trigger: str = "PreToolUse",
) -> tuple[replay.ValidatedPlan, replay.ValidatedSession]:
    session = _session(tmp_path, trigger=trigger)
    plan_path = _write_plan(tmp_path, [session])
    plan = replay.validate_plan(plan_path, study_root=tmp_path)
    return plan, plan.sessions[session["session_id"]]


def test_protocol_v3_trigger_contract_is_pinned_to_rap_adapter():
    protocol, digest = replay._validate_protocol(replay.PROTOCOL_PATH)

    assert digest == replay.PROTOCOL_SHA256
    assert protocol["protocol_version"] == "3.0.0"
    assert replay.SUPPORTED_FIELDS == {
        "Stop": "/last_assistant_message",
        "PreToolUse": "/tool_input",
        "PostToolUse": "/tool_response",
        "UserPromptSubmit": "/prompt",
    }


def test_pilot_plan_is_valid_but_explicitly_non_study(tmp_path):
    plan, session = _validated_pilot(tmp_path)

    assert plan.raw["study_mode"] == replay.PILOT
    assert len(plan.sessions) == 1
    assert session.raw["trigger"] == "PreToolUse"


def test_formal_plan_requires_all_48_paired_sessions(tmp_path):
    session = _session(tmp_path)
    plan_path = _write_plan(tmp_path, [session], study_mode=replay.FORMAL)

    with pytest.raises(replay.HarnessFailure) as raised:
        replay.validate_plan(plan_path, study_root=tmp_path)

    assert raised.value.code == "formal_design_incomplete"


def test_complete_formal_pair_structure_validates(tmp_path):
    sessions = []
    conditions = sorted(replay.CONDITIONS)
    for rule_index in range(1, 9):
        rule_id = f"{rule_index:016d}"
        rule_path = _write_rule(tmp_path, rule_id)
        for task_index in range(1, 4):
            prompt_path = tmp_path / "tasks" / f"r{rule_index}-t{task_index}.txt"
            prompt_path.parent.mkdir(parents=True, exist_ok=True)
            prompt_path.write_text(
                f"Complete rule {rule_index} task {task_index}.\n", encoding="utf-8"
            )
            for condition_index, condition in enumerate(conditions):
                sessions.append(
                    _session(
                        tmp_path,
                        rule_id=rule_id,
                        session_id=(
                            f"rule-{rule_index}-task-{task_index}-c{condition_index}"
                        ),
                        task_id=f"task-{task_index}",
                        condition=condition,
                        repository_commit=("a" * 39 + str(condition_index)),
                        rule_path=rule_path,
                        prompt_path=prompt_path,
                    )
                )
    plan_path = _write_plan(tmp_path, sessions, study_mode=replay.FORMAL)

    plan = replay.validate_plan(plan_path, study_root=tmp_path)

    assert len(plan.sessions) == 48
    assert len({item.raw["rule_id"] for item in plan.sessions.values()}) == 8


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda plan: plan.update({"unknown": True}), "plan_schema_invalid"),
        (
            lambda plan: plan["sessions"][0].update(
                {"repository_url": "https://token@example.com/private.git"}
            ),
            "repository_not_public_https",
        ),
        (
            lambda plan: plan["sessions"][0].update(
                {"input_pointer": "/unsupported"}
            ),
            "ineligible_trigger_field",
        ),
    ],
)
def test_plan_schema_and_eligibility_failures_have_named_codes(
    tmp_path, mutation, code
):
    session = _session(tmp_path)
    plan_path = _write_plan(tmp_path, [session])
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    mutation(plan)
    plan_path.write_text(json.dumps(plan), encoding="utf-8")

    with pytest.raises(replay.HarnessFailure) as raised:
        replay.validate_plan(plan_path, study_root=tmp_path)

    assert raised.value.code == code


def test_plan_rejects_task_prompt_hash_drift(tmp_path):
    session = _session(tmp_path)
    plan_path = _write_plan(tmp_path, [session])
    (tmp_path / session["task_prompt_path"]).write_text(
        "Changed after freeze.\n", encoding="utf-8"
    )

    with pytest.raises(replay.HarnessFailure) as raised:
        replay.validate_plan(plan_path, study_root=tmp_path)

    assert raised.value.code == "task_prompt_hash_mismatch"


def test_hook_capture_preserves_exact_stdin_and_records_invalid_schema(tmp_path):
    raw_text = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "thread-1",
            "turn_id": "turn-1",
            "tool_use_id": "tool-1",
            "tool_input": {"z": 2, "a": 1},
        },
        separators=(",", ":"),
    )

    good = replay.capture_hook(tmp_path, raw_text)
    bad = replay.capture_hook(tmp_path, "[]")
    loaded = replay._load_capture_records(tmp_path)

    assert good["capture_ok"] is True
    assert bad["capture_ok"] is False
    assert loaded[0]["raw_text"] == raw_text
    assert loaded[0]["raw_text_sha256"] == replay._sha256_text(raw_text)
    assert loaded[1]["capture_error"].startswith("ValueError:")


def test_exact_field_extraction_uses_rap_serialization_and_labels_pilot(tmp_path):
    _plan, session = _validated_pilot(tmp_path)
    raw_text = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "session_id": "thread-1",
            "turn_id": "turn-1",
            "tool_name": "shell",
            "tool_use_id": "tool-1",
            "tool_input": {"z": 2, "a": 1},
            "cwd": str(tmp_path),
        }
    )
    records = [
        {
            "capture_ok": True,
            "capture_file": "one.json",
            "raw_text": raw_text,
        }
    ]

    rows = replay.extract_fields(
        records,
        session=session,
        study_mode=replay.PILOT,
        codex_thread_id="thread-1",
    )

    assert rows[0]["field"] == '{\n  "a": 1,\n  "z": 2\n}'
    assert rows[0]["json_pointer"] == "/tool_input"
    assert rows[0]["value_type"] == "object"
    assert rows[0]["event_id"] == "tool-1"
    assert rows[0]["event_id_source"] == "raw_payload.tool_use_id"
    assert rows[0]["study_mode"] == "pilot_non_study"
    assert rows[0]["study_eligible"] is False


def test_exact_field_extraction_fails_on_missing_field_or_session_mismatch(tmp_path):
    _plan, session = _validated_pilot(tmp_path)
    base = {
        "hook_event_name": "PreToolUse",
        "session_id": "thread-1",
        "turn_id": "turn-1",
        "tool_use_id": "tool-1",
    }

    with pytest.raises(replay.HarnessFailure) as missing:
        replay.extract_fields(
            [
                {
                    "capture_ok": True,
                    "capture_file": "one.json",
                    "raw_text": json.dumps(base),
                }
            ],
            session=session,
            study_mode=replay.PILOT,
            codex_thread_id="thread-1",
        )
    assert missing.value.code == "declared_field_unavailable"

    with pytest.raises(replay.HarnessFailure) as mismatch:
        replay.extract_fields(
            [
                {
                    "capture_ok": True,
                    "capture_file": "one.json",
                    "raw_text": json.dumps({**base, "tool_input": {}, "session_id": "x"}),
                }
            ],
            session=session,
            study_mode=replay.PILOT,
            codex_thread_id="thread-1",
        )
    assert mismatch.value.code == "codex_hook_session_mismatch"


def test_sha256_bottom_k_cap_is_exact_and_input_order_independent():
    rows = [
        {"event_id": f"event-{index}", "sequence": index} for index in range(50)
    ]
    expected = {
        row["event_id"]
        for row in sorted(
            rows,
            key=lambda row: replay.reservoir_rank("session", row["event_id"]),
        )[:30]
    }

    selected, report = replay.apply_reservoir_cap(rows, session_id="session")
    reversed_selected, _ = replay.apply_reservoir_cap(
        list(reversed(rows)), session_id="session"
    )

    assert {row["event_id"] for row in selected} == expected
    assert {row["event_id"] for row in reversed_selected} == expected
    assert [row["sequence"] for row in selected] == sorted(
        row["sequence"] for row in selected
    )
    assert report["matching_events"] == 50
    assert report["retained_events"] == 30
    assert report["sampling_fraction"] == 0.6
    assert len(report["rank_threshold_sha256"]) == 64


def test_sha256_cap_rejects_duplicate_event_ids():
    with pytest.raises(replay.HarnessFailure) as raised:
        replay.apply_reservoir_cap(
            [
                {"event_id": "same", "sequence": 0},
                {"event_id": "same", "sequence": 1},
            ],
            session_id="session",
        )

    assert raised.value.code == "duplicate_event_id"


def test_codex_jsonl_requires_one_thread_and_one_terminal_event():
    stream = (
        '{"type":"thread.started","thread_id":"thread-1"}\n'
        '{"type":"turn.started"}\n'
        '{"type":"item.started","item":{"id":"tool-1",'
        '"type":"command_execution"}}\n'
        '{"type":"item.completed","item":{"id":"message-1",'
        '"type":"agent_message","text":"Done"}}\n'
        '{"type":"turn.completed","usage":{}}\n'
    ).encode()

    parsed = replay._parse_codex_jsonl(stream)

    assert parsed["thread_id"] == "thread-1"
    assert parsed["terminal_type"] == "turn.completed"
    assert parsed["tool_item_count"] == 1
    with pytest.raises(replay.HarnessFailure) as raised:
        replay._parse_codex_jsonl(b'{"type":"turn.completed"}\n')
    assert raised.value.code == "codex_jsonl_schema_invalid"


def test_isolated_config_hooks_and_command_pin_every_setting(tmp_path):
    _plan, session = _validated_pilot(tmp_path)
    settings = _settings()
    capture_dir = tmp_path / "captures"

    config = replay.render_isolated_codex_config(settings)
    hooks = replay.render_capture_hooks("PreToolUse", capture_dir)
    command = replay.build_codex_command(
        Path("/pinned/codex"),
        checkout=tmp_path / "checkout",
        session=session,
        settings=settings,
    )

    assert 'model = "gpt-test-pinned"' in config
    assert 'model_reasoning_effort = "high"' in config
    assert 'approval_policy = "never"' in config
    assert 'sandbox_mode = "workspace-write"' in config
    assert "sandbox_workspace_write.network_access = false" in config
    assert 'web_search = "disabled"' in config
    assert 'shell_environment_policy.inherit = "core"' in config
    assert "shell_environment_policy.ignore_default_excludes = false" in config
    handler = hooks["hooks"]["PreToolUse"][0]["hooks"][0]
    assert handler["async"] is False
    hook_argv = shlex.split(handler["command"])
    assert hook_argv[-2:] == ["--capture-dir", str(capture_dir)]
    assert command[:4] == ["/pinned/codex", "exec", "--json", "--ephemeral"]
    assert "--strict-config" in command
    assert "--dangerously-bypass-hook-trust" in command
    assert command[command.index("--model") + 1] == "gpt-test-pinned"
    assert command[command.index("--sandbox") + 1] == "workspace-write"
    assert "--ignore-rules" in command
    assert command[-1] == session.task_prompt


def test_codex_binary_hash_and_version_are_both_verified(tmp_path):
    binary = tmp_path / "codex"
    binary.write_bytes(b"fake-codex")
    binary.chmod(0o700)
    settings = _settings()
    settings["executable_sha256"] = replay._sha256_file(binary)

    def fake_run(*_args, **_kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout="codex-cli 0.test\n",
            stderr="diagnostic\n",
        )

    receipt = replay.verify_codex_binary(binary, settings, run=fake_run)

    assert receipt["sha256"] == settings["executable_sha256"]
    assert receipt["version"] == "codex-cli 0.test"
    settings["version"] = "codex-cli other"
    with pytest.raises(replay.HarnessFailure) as raised:
        replay.verify_codex_binary(binary, settings, run=fake_run)
    assert raised.value.code == "codex_version_mismatch"


def test_fake_session_writes_separate_atomic_raw_and_provenance_outputs(
    tmp_path, monkeypatch
):
    plan, session = _validated_pilot(tmp_path, trigger="Stop")
    output_dir = tmp_path / "outputs"
    binary = tmp_path / "codex"
    binary.write_bytes(b"fake")
    binary.chmod(0o700)
    monkeypatch.setattr(
        replay,
        "verify_codex_binary",
        lambda *_args, **_kwargs: {
            "path_basename": "codex",
            "sha256": "b" * 64,
            "version": "codex-cli 0.test",
            "version_stderr_sha256": "d" * 64,
        },
    )

    def fake_checkout(_session, destination):
        destination.mkdir()
        return {
            "repository_url": _session.raw["repository_url"],
            "commit": _session.raw["repository_commit"],
            "pre_run_status_sha256": replay._sha256_text(""),
        }

    monkeypatch.setattr(replay, "fresh_checkout", fake_checkout)
    monkeypatch.setattr(
        replay,
        "_run_git",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="", stderr="", returncode=0),
    )

    stdout_bytes = (
        b'{"type":"thread.started","thread_id":"thread-1"}\n'
        b'{"type":"turn.started"}\n'
        b'{"type":"item.completed","item":{"id":"message-1",'
        b'"type":"agent_message","text":"Done"}}\n'
        b'{"type":"turn.completed","usage":{}}\n'
    )

    def fake_codex_run(command, *, stdout, stderr, env, timeout, check):
        assert command[1:4] == ["exec", "--json", "--ephemeral"]
        assert timeout == 120
        assert check is False
        isolated_home = Path(env["CODEX_HOME"])
        hooks = json.loads((isolated_home / "hooks.json").read_text())
        handler = hooks["hooks"]["Stop"][0]["hooks"][0]
        hook_argv = shlex.split(handler["command"])
        capture_dir = Path(hook_argv[hook_argv.index("--capture-dir") + 1])
        replay.capture_hook(
            capture_dir,
            json.dumps(
                {
                    "hook_event_name": "Stop",
                    "session_id": "thread-1",
                    "turn_id": "turn-1",
                    "last_assistant_message": "Done",
                }
            ),
        )
        stdout.write(stdout_bytes)
        stderr.write(b"stderr-only diagnostic\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(replay.subprocess, "run", fake_codex_run)
    monkeypatch.setattr(replay.platform, "platform", lambda: "test-platform")
    monkeypatch.setattr(replay.platform, "machine", lambda: "test-machine")

    manifest = replay.run_session(
        plan=plan,
        session_id=session.raw["session_id"],
        attempt_id="pilot-1",
        output_dir=output_dir,
        codex_binary=binary,
        auth_source=None,
    )

    paths = replay._artifact_paths(output_dir, session.raw["session_id"], "pilot-1")
    assert paths["codex_stdout"].read_bytes() == stdout_bytes
    assert paths["codex_stderr"].read_bytes() == b"stderr-only diagnostic\n"
    fields = [json.loads(line) for line in paths["fields"].read_text().splitlines()]
    assert fields[0]["field"] == "Done"
    assert fields[0]["study_eligible"] is False
    assert manifest["status"] == "complete"
    assert manifest["study_mode"] == "pilot_non_study"
    assert manifest["study_eligible"] is False
    assert manifest["pilot_label"] == "non-study interface/infrastructure pilot"
    assert manifest["isolated_runtime"]["stdout_stderr_separated"] is True
    assert not list(output_dir.glob("*.tmp"))


def test_fake_schema_failure_preserves_raw_attempt_and_named_failure_manifest(
    tmp_path, monkeypatch
):
    plan, session = _validated_pilot(tmp_path, trigger="Stop")
    output_dir = tmp_path / "outputs"
    binary = tmp_path / "codex"
    binary.write_bytes(b"fake")
    binary.chmod(0o700)
    monkeypatch.setattr(
        replay,
        "verify_codex_binary",
        lambda *_args, **_kwargs: {},
    )

    def fake_checkout(_session, destination):
        destination.mkdir()
        return {}

    monkeypatch.setattr(replay, "fresh_checkout", fake_checkout)

    def fake_codex_run(_command, *, stdout, stderr, **_kwargs):
        stdout.write(b"not-json\n")
        stderr.write(b"diagnostic\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(replay.subprocess, "run", fake_codex_run)

    with pytest.raises(replay.HarnessFailure) as raised:
        replay.run_session(
            plan=plan,
            session_id=session.raw["session_id"],
            attempt_id="failed-1",
            output_dir=output_dir,
            codex_binary=binary,
            auth_source=None,
        )

    assert raised.value.code == "codex_jsonl_invalid"
    paths = replay._artifact_paths(output_dir, session.raw["session_id"], "failed-1")
    assert paths["codex_stdout"].read_bytes() == b"not-json\n"
    failure = json.loads(paths["manifest"].read_text())
    assert failure["status"] == "failed"
    assert failure["failure"]["code"] == "codex_jsonl_invalid"
    assert failure["study_eligible"] is False
    assert paths["raw_hooks"].read_text() == ""
    assert paths["fields"].read_text() == ""
    assert not list(output_dir.glob("*.tmp"))


def test_codex_environment_uses_isolated_home_without_secret_values(tmp_path):
    old_home = os.environ.get("CODEX_HOME")
    environment, receipt = replay._codex_environment(tmp_path / "isolated")

    assert environment["CODEX_HOME"] == str(tmp_path / "isolated")
    if old_home is not None:
        assert old_home not in json.dumps(receipt)
    assert all("KEY" not in key or key == "codex_api_key_present" for key in receipt)
