from rules_as_programs.core import evaluation_log


def _start(evaluation_id: str, rule_id: str = "rule"):
    return {
        "evaluation_id": evaluation_id,
        "timestamp": 10.0,
        "project_root": "/project",
        "conversation_id": "conversation",
        "rule": {"id": rule_id, "name": "Rule"},
        "trigger": {"hook": "Stop", "event_id": "event"},
        "input": {
            "json_pointer": "/text",
            "pointer_source": "default",
            "text": "input",
            "sha256": "hash",
            "byte_count": 5,
        },
    }


def test_evaluation_journal_pairs_all_outcomes(monkeypatch, tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    evaluation_log.started(str(project), _start("ok"))
    evaluation_log.completed(str(project), {
        "evaluation_id": "ok",
        "timestamp": 11.0,
        "duration_ms": 42,
        "result": "OK",
        "finding_id": None,
    })
    evaluation_log.started(str(project), _start("warning"))
    evaluation_log.completed(str(project), {
        "evaluation_id": "warning",
        "timestamp": 12.0,
        "duration_ms": 61,
        "result": "WARNING",
        "finding_id": 7,
    })
    evaluation_log.started(str(project), _start("error", "other"))
    evaluation_log.failed(str(project), {
        "evaluation_id": "error",
        "timestamp": 13.0,
        "duration_ms": 8100,
        "error_code": "inference_timeout",
        "error": "timed out",
    })

    rows = evaluation_log.history(str(project))

    assert [row["evaluation_id"] for row in rows] == [
        "error", "warning", "ok"]
    assert rows[0]["status"] == "failed"
    assert rows[1]["result"] == "WARNING"
    assert rows[1]["finding_id"] == 7
    assert rows[2]["result"] == "OK"
    assert evaluation_log.history(
        str(project), rule_id="rule")[0]["evaluation_id"] == "warning"


def test_evaluation_journal_rotates(monkeypatch, tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr(evaluation_log, "MAX_LOG_BYTES", 120)
    for index in range(8):
        evaluation_log.started(str(project), _start(f"evaluation-{index}"))

    path = evaluation_log.config.project_evaluation_log_file(str(project))
    assert path.exists()
    assert path.with_name(f"{path.name}.1").exists()
