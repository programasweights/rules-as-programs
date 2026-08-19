from rules_as_programs.core.validation_store import ValidationResultStore


def test_validation_results_persist_and_match_per_case(tmp_path):
    path = tmp_path / "validation.db"
    store = ValidationResultStore(path)
    cases = [
        {"id": "one", "input": "safe", "expected": "OK"},
        {"id": "two", "input": "risky", "expected": "WARNING"},
    ]
    recorded = store.record(
        project_root="/project",
        rule_id="rule",
        spec="classify input",
        compiler="future-standard",
        compiler_snapshot="snapshot-1",
        program_id="program-1",
        results=[
            {**cases[0], "actual": "OK", "valid_output": True, "ok": True},
            {
                **cases[1],
                "actual": "WARNING",
                "valid_output": True,
                "ok": True,
            },
        ],
    )

    reopened = ValidationResultStore(path)
    remaining = reopened.matching(
        project_root="/project",
        rule_id="rule",
        spec="classify input",
        compiler="future-standard",
        compiler_snapshot="snapshot-1",
        cases=[cases[1]],
    )

    assert len(recorded) == 2
    assert [item["id"] for item in remaining] == ["two"]
    assert remaining[0]["actual"] == "WARNING"


def test_validation_result_identity_includes_case_spec_and_compiler(tmp_path):
    store = ValidationResultStore(tmp_path / "validation.db")
    case = {"id": "case", "input": "safe", "expected": "OK"}
    store.record(
        project_root="/project",
        rule_id="rule",
        spec="spec one",
        compiler="standard",
        compiler_snapshot="snapshot-1",
        program_id="program-1",
        results=[
            {**case, "actual": "OK", "valid_output": True, "ok": True}
        ],
    )

    def matching(**changes):
        values = {
            "project_root": "/project",
            "rule_id": "rule",
            "spec": "spec one",
            "compiler": "standard",
            "compiler_snapshot": "snapshot-1",
            "cases": [case],
        }
        values.update(changes)
        return store.matching(**values)

    assert len(matching()) == 1
    assert len(matching(program_id="program-1")) == 1
    assert not matching(program_id="program-2")
    assert not matching(spec="spec two")
    assert not matching(compiler="finetuned")
    assert not matching(compiler_snapshot="snapshot-2")
    assert not matching(cases=[{**case, "expected": "WARNING"}])
