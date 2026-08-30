#!/usr/bin/env python3
"""Run the frozen deterministic RAP provenance workflow.

This experiment uses only synthetic inputs and isolated temporary state. The
judge outputs are fixed by fixture revision so the experiment tests RAP's
record linkage and revision semantics, not fuzzy-judge quality or usability.

Run without ``--write`` to verify that a fresh run exactly matches the frozen
JSON output. ``--write`` is reserved for intentionally refreshing that file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from rules_as_programs import rules_api
from rules_as_programs.adapters.codex.adapter import normalize
from rules_as_programs.core import audit, evaluation_log, revisions
from rules_as_programs.core.engine import Engine
from rules_as_programs.core.ledger import LedgerStore
from rules_as_programs.core.store import VerdictStore
from rules_as_programs.daemon import Daemon, _RulesCache


ROOT = Path(__file__).resolve().parent
FROZEN_OUTPUT = ROOT / "outputs" / "frozen" / "provenance-workflow.json"
RULE_ID = "pr0v3nanc3w0rkf1"
RULE_NAME = "Synthetic completion-evidence fixture"
COMPILER = "fixture-compiler"
INITIAL_SNAPSHOT = "fixture-snapshot-v1"
INITIAL_PROGRAM = "fixture-program-v1"
REVISED_SNAPSHOT = "fixture-snapshot-v2"
REVISED_PROGRAM = "fixture-program-v2"
INPUT_TEXT = (
    "Done—the parser fix is verified by `pytest tests/test_parser.py -q` (12 passed)."
)

INITIAL_SPEC = """Decide whether the response makes a completion claim.
Return WARNING for every completion claim, even when evidence is reported.
Return ONLY one of: OK, INFO, WARNING, CRITICAL

Input: Done—the parser fix is complete.
Output: WARNING

Input: I have not completed the parser fix.
Output: OK"""

REVISED_SPEC = """Decide whether the response makes a completion claim without
reporting concrete verification evidence. A named check and its observed
outcome count as evidence.
Return ONLY one of: OK, INFO, WARNING, CRITICAL

Input: Done—the parser fix is complete.
Output: WARNING

Input: Done—the parser fix is verified by pytest (12 passed).
Output: OK"""


def _source(spec: str) -> str:
    rendered_spec = spec.replace('"""', r"\"\"\"")
    return f'''from rules_as_programs import rule

SPEC = """{rendered_spec}"""

@rule(
    id="{RULE_ID}",
    name="{RULE_NAME}",
    trigger="Stop",
    spec=SPEC,
)
def synthetic_completion_evidence(ctx):
    "Synthetic rule used only by the provenance workflow fixture."
    decision = ctx.paw(SPEC)(ctx.input)
    return ctx.result(decision)
'''


class FixtureRuntime:
    """Deterministic judge outputs keyed by the active program revision."""

    available = True

    def program_id_for_spec(
        self, spec: str, _compiler: str | None = None, timeout: float | None = None
    ) -> str:
        del timeout
        if spec.strip() == INITIAL_SPEC.strip():
            return INITIAL_PROGRAM
        if spec.strip() == REVISED_SPEC.strip():
            return REVISED_PROGRAM
        raise AssertionError("unexpected specification")

    def run(self, program_id: str, text: str) -> str:
        if text != INPUT_TEXT:
            raise AssertionError("fixture judge received the wrong input")
        outputs = {
            INITIAL_PROGRAM: "WARNING",
            REVISED_PROGRAM: "OK",
        }
        return outputs[program_id]


@contextmanager
def _isolated_environment(root: Path) -> Iterator[None]:
    previous = {name: os.environ.get(name) for name in ("RAP_STATE_DIR", "CODEX_HOME")}
    os.environ["RAP_STATE_DIR"] = str(root / "state")
    os.environ["CODEX_HOME"] = str(root / "codex-home")
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _single_rule(cache: _RulesCache, project_root: str):
    loaded = cache.get(project_root)
    rules = [rule for rule in loaded if rule.id == RULE_ID]
    if len(rules) != 1:
        errors = [error.error for error in cache.errors(project_root)]
        rule_dir = Path(project_root) / ".codex" / "rules-as-programs" / "rules"
        paths = [str(path.relative_to(project_root)) for path in rule_dir.rglob("*")]
        raise AssertionError(
            f"expected one active fixture rule, found {len(rules)}; "
            f"loaded={[rule.id for rule in loaded]!r}; errors={errors!r}; "
            f"paths={paths!r}"
        )
    return rules[0]


def _record(
    assertions: list[dict[str, Any]], assertion_id: str, condition: bool
) -> None:
    passed = bool(condition)
    assertions.append({"id": assertion_id, "passed": passed})
    if not passed:
        raise AssertionError(assertion_id)


def run_experiment() -> dict[str, Any]:
    assertions: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="rap-provenance-") as temporary:
        isolated_root = Path(temporary)
        with _isolated_environment(isolated_root):
            project = isolated_root / "synthetic-project"
            project.mkdir()
            project = project.resolve()

            initial_saved = rules_api.save_rule(
                RULE_ID, _source(INITIAL_SPEC), "project", str(project)
            )
            if not initial_saved.get("ok"):
                raise AssertionError(initial_saved.get("error", "initial save failed"))
            source_path = Path(str(initial_saved["path"]))
            initial_source = str(initial_saved["source"])
            initial_active = revisions.activate(
                RULE_ID,
                source_path,
                initial_source,
                compiler=COMPILER,
                program_id=INITIAL_PROGRAM,
                compiler_snapshot=INITIAL_SNAPSHOT,
                compiler_mode=revisions.EXPLICIT_COMPILER_MODE,
            )

            runtime = FixtureRuntime()
            store = VerdictStore()
            ledgers = LedgerStore()
            cache = _RulesCache()
            engine = Engine(
                runtime,
                store,
                cache.get,
                is_enabled=lambda *_args: True,
            )
            daemon = Daemon.__new__(Daemon)
            daemon.store = store
            daemon.ledgers = ledgers

            raw_initial = {
                "session_id": "synthetic-provenance-session",
                "turn_id": "initial-turn",
                "hook_event_name": "Stop",
                "cwd": str(project),
                "last_assistant_message": INPUT_TEXT,
            }
            initial_events = normalize(raw_initial)
            initial_events[0].id = "synthetic-stop-initial"
            initial_events[0].ts = 1.0
            initial_events[1].id = "synthetic-checkpoint-initial"
            initial_events[1].ts = 1.1
            initial_trigger = initial_events[0]
            ledger = ledgers.get(initial_trigger.conversation_id, str(project))
            initial_verdicts = []
            for event in initial_events:
                ledger.append(event)
                initial_verdicts.extend(engine.on_event(event, ledger))
            if len(initial_verdicts) != 1:
                raise AssertionError(
                    f"expected one initial finding, found {len(initial_verdicts)}"
                )
            verdict = initial_verdicts[0]
            if verdict.id is None:
                raise AssertionError("initial finding has no stable ID")
            initial_finding_id = int(verdict.id)
            initial_store_record = store.get(initial_finding_id)
            initial_audit = audit.read_finding(str(project), initial_finding_id)
            initial_history = evaluation_log.history(
                str(project), rule_id=RULE_ID, limit=10
            )
            if not initial_store_record or not initial_audit or not initial_history:
                raise AssertionError("initial provenance records are incomplete")
            evaluation = dict(initial_audit["evaluation"])
            evaluated_input = dict(evaluation["input"])
            history_row = initial_history[0]

            _record(
                assertions,
                "stop_input_mapping_exact",
                evaluated_input.get("json_pointer") == "/last_assistant_message"
                and evaluated_input.get("pointer_source") == "default",
            )
            _record(
                assertions,
                "input_text_and_bytes_exact",
                evaluated_input.get("text") == INPUT_TEXT
                and evaluated_input.get("byte_count") == len(INPUT_TEXT.encode("utf-8"))
                and evaluated_input.get("char_count") == len(INPUT_TEXT),
            )
            _record(
                assertions,
                "input_sha256_exact",
                evaluated_input.get("sha256") == _sha256(INPUT_TEXT),
            )
            _record(
                assertions,
                "event_linkage_exact",
                evaluated_input.get("event_ids") == [initial_trigger.id]
                and evaluation.get("trigger", {}).get("event_id") == initial_trigger.id
                and initial_store_record.get("trigger_event_id") == initial_trigger.id,
            )
            _record(
                assertions,
                "evaluation_and_finding_linkage_exact",
                evaluation.get("evaluation_id") == history_row.get("evaluation_id")
                and history_row.get("finding_id") == initial_finding_id
                and initial_store_record.get("evaluation", {}).get("evaluation_id")
                == evaluation.get("evaluation_id"),
            )

            saved_case = daemon.dispatch(
                {
                    "type": "add_validation_case",
                    "rule_id": RULE_ID,
                    "project_root": str(project),
                    "input": evaluated_input["text"],
                    "expected": "OK",
                }
            )
            if not saved_case.get("ok"):
                raise AssertionError(saved_case.get("error", "save-as-test failed"))
            validation_cases = rules_api.validation_cases(RULE_ID, str(project))
            _record(
                assertions,
                "save_as_test_copies_exact_input",
                len(validation_cases) == 1
                and validation_cases[0].get("input") == INPUT_TEXT
                and validation_cases[0].get("expected") == "OK",
            )
            _record(
                assertions,
                "validation_case_is_separate_from_spec",
                source_path.read_text(encoding="utf-8") == initial_source
                and INPUT_TEXT not in initial_source
                and (source_path.parent / "tests.json").is_file(),
            )

            revised_saved = rules_api.save_rule(
                RULE_ID, _source(REVISED_SPEC), "project", str(project)
            )
            if not revised_saved.get("ok"):
                raise AssertionError(revised_saved.get("error", "revised save failed"))
            revised_source = str(revised_saved["source"])
            revised_active = revisions.activate(
                RULE_ID,
                source_path,
                revised_source,
                compiler=COMPILER,
                program_id=REVISED_PROGRAM,
                compiler_snapshot=REVISED_SNAPSHOT,
                compiler_mode=revisions.EXPLICIT_COMPILER_MODE,
            )
            cache.invalidate()
            _single_rule(cache, str(project))

            _record(
                assertions,
                "behavior_hash_changes_with_spec_revision",
                initial_active["behavior_hash"] != revised_active["behavior_hash"],
            )

            stale_groups = daemon.dispatch(
                {
                    "type": "finding_groups",
                    "project_root": str(project),
                    "include_reviewed": True,
                }
            )
            old_detail = daemon.dispatch(
                {"type": "finding_detail", "id": initial_finding_id}
            )
            if not old_detail.get("ok"):
                raise AssertionError(
                    old_detail.get("error", "finding retrieval failed")
                )
            old_evaluation = dict(old_detail["evaluation"])
            old_rule = dict(old_evaluation["rule"])
            groups = list(stale_groups.get("groups") or [])
            old_group = next(
                (group for group in groups if group.get("id") == initial_finding_id),
                groups[0] if len(groups) == 1 else None,
            )

            _record(
                assertions,
                "initial_source_revision_retained",
                old_rule.get("source") == initial_source
                and old_rule.get("source_hash") == initial_active["source_hash"]
                and old_detail.get("recorded_rule_projection", {}).get("spec")
                == INITIAL_SPEC,
            )
            _record(
                assertions,
                "initial_behavior_revision_retained",
                old_rule.get("behavior_hash") == initial_active["behavior_hash"]
                and old_detail.get("recorded_behavior_hash")
                == initial_active["behavior_hash"],
            )
            _record(
                assertions,
                "compiler_snapshot_retained",
                old_rule.get("compiler") == COMPILER
                and old_rule.get("compiler_snapshot") == INITIAL_SNAPSHOT,
            )
            _record(
                assertions,
                "program_id_retained",
                old_rule.get("program_id") == INITIAL_PROGRAM,
            )
            _record(
                assertions,
                "old_finding_marked_stale",
                bool(old_group)
                and old_group.get("stale") is True
                and old_detail.get("rule_changed") is True
                and old_detail.get("current_behavior_hash")
                == revised_active["behavior_hash"],
            )

            raw_replay = {**raw_initial, "turn_id": "revised-turn"}
            replay_events = normalize(raw_replay)
            replay_events[0].id = "synthetic-stop-revised"
            replay_events[0].ts = 2.0
            replay_events[1].id = "synthetic-checkpoint-revised"
            replay_events[1].ts = 2.1
            findings_before_replay = len(
                store.recent(
                    limit=100,
                    project_root=str(project),
                    include_acknowledged=True,
                )
            )
            replay_verdicts = []
            for event in replay_events:
                ledger.append(event)
                replay_verdicts.extend(engine.on_event(event, ledger))
            history_after_replay = evaluation_log.history(
                str(project), rule_id=RULE_ID, limit=10
            )
            findings_after_replay = len(
                store.recent(
                    limit=100,
                    project_root=str(project),
                    include_acknowledged=True,
                )
            )
            latest = history_after_replay[0]
            _record(
                assertions,
                "revised_replay_is_ok_without_new_finding",
                not replay_verdicts
                and latest.get("result") == "OK"
                and latest.get("finding_id") is None
                and findings_after_replay == findings_before_replay == 1,
            )

            retrieved_after_replay = daemon.dispatch(
                {"type": "finding_detail", "id": initial_finding_id}
            )
            _record(
                assertions,
                "old_finding_retrievable_after_replay",
                retrieved_after_replay.get("ok") is True
                and retrieved_after_replay.get("evaluation", {}).get("evaluation_id")
                == evaluation.get("evaluation_id")
                and audit.read_finding(str(project), initial_finding_id) is not None,
            )

            output = {
                "schema_version": 1,
                "experiment": "rap-deterministic-provenance-workflow-v1",
                "scope": (
                    "Synthetic deterministic fixture testing record linkage and "
                    "revision semantics; not judge quality or human usability."
                ),
                "fixture": {
                    "rule_id": RULE_ID,
                    "trigger": "Stop",
                    "json_pointer": "/last_assistant_message",
                    "input_char_count": len(INPUT_TEXT),
                    "input_byte_count": len(INPUT_TEXT.encode("utf-8")),
                    "input_sha256": _sha256(INPUT_TEXT),
                    "initial_source_sha256": initial_active["source_hash"],
                    "initial_behavior_sha256": initial_active["behavior_hash"],
                    "revised_source_sha256": revised_active["source_hash"],
                    "revised_behavior_sha256": revised_active["behavior_hash"],
                    "initial_compiler": COMPILER,
                    "initial_compiler_snapshot": INITIAL_SNAPSHOT,
                    "initial_program_id": INITIAL_PROGRAM,
                    "revised_compiler_snapshot": REVISED_SNAPSHOT,
                    "revised_program_id": REVISED_PROGRAM,
                },
                "assertions": assertions,
                "assertions_passed": sum(
                    assertion["passed"] for assertion in assertions
                ),
                "assertions_total": len(assertions),
                "all_passed": all(assertion["passed"] for assertion in assertions),
            }
    return output


def _render(output: dict[str, Any]) -> str:
    return json.dumps(output, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=FROZEN_OUTPUT)
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace the frozen output instead of checking it",
    )
    args = parser.parse_args()

    rendered = _render(run_experiment())
    if args.write:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(rendered, encoding="utf-8")
        os.replace(temporary, args.output)
        print(f"wrote {args.output}")
        print(rendered, end="")
        return 0

    if not args.output.is_file():
        print(f"frozen output is missing: {args.output}")
        return 1
    frozen = args.output.read_text(encoding="utf-8")
    if frozen != rendered:
        print(f"fresh result differs from frozen output: {args.output}")
        return 1
    print(f"verified {args.output}")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
