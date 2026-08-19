import json

from rules_as_programs import config, rules_api
from rules_as_programs.core.rule import new_rule_id


def test_validation_cases_are_separate_from_rule_spec(tmp_path):
    source_path = tmp_path / "rule" / "rule.py"
    source_path.parent.mkdir()
    source_path.write_text("SPEC = 'unchanged'\n")
    result = rules_api.save_validation_cases(str(source_path), [
        {
            "id": "case-ok",
            "input": "git push",
            "expected": "OK",
            "note": "normal sync",
        },
        {
            "id": "case-warning",
            "input": "rsync src/ host:/app",
            "expected": "warning",
        },
    ])

    assert result["ok"]
    assert source_path.read_text() == "SPEC = 'unchanged'\n"
    assert rules_api.validation_cases_for_path(str(source_path)) == [
        {
            "id": "case-ok",
            "input": "git push",
            "expected": "OK",
            "note": "normal sync",
        },
        {
            "id": "case-warning",
            "input": "rsync src/ host:/app",
            "expected": "WARNING",
            "note": "",
        },
    ]
    stored = json.loads((source_path.parent / "tests.json").read_text())
    assert stored["version"] == 1


def test_invalid_validation_cases_are_not_persisted(tmp_path):
    source_path = tmp_path / "rule.py"
    source_path.write_text("# rule\n")
    result = rules_api.save_validation_cases(str(source_path), [
        {"input": "", "expected": "OK"},
        {"input": "input", "expected": "UNKNOWN"},
    ])
    assert result["ok"]
    assert result["cases"] == []


def test_rule_get_includes_saved_validation_cases(monkeypatch, tmp_path):
    monkeypatch.setattr(
        config, "global_rules_dir", lambda: tmp_path / "global-rules")
    rule_id = new_rule_id()
    source = rules_api.draft_rule_source(rule_id, "Validation metadata")
    saved = rules_api.save_rule(rule_id, source, "global", None)
    rules_api.save_validation_cases(saved["path"], [{
        "id": "case",
        "input": "git push",
        "expected": "OK",
    }])

    info = rules_api.get_rule(rule_id, None)

    assert info["validation_cases"] == [{
        "id": "case",
        "input": "git push",
        "expected": "OK",
        "note": "",
    }]
