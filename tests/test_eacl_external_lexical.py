from __future__ import annotations

import json

import pytest

from experiments.eacl2027.run_benchmark import _lexical


def _event(**fields: str) -> str:
    return json.dumps(fields, sort_keys=True)


@pytest.mark.parametrize(
    ("rule_id", "event"),
    [
        ("98z9wvr031840p4g", _event(command="npm ci")),
        ("98z9wvr031840p4g", _event(command="corepack yarn install")),
        ("98z9wvr031840p4g", _event(command="bash -lc 'npm test'")),
        (
            "g3b7damk0b5xgdj6",
            _event(command="git commit -m 'Generated with Claude Code'"),
        ),
        (
            "g3b7damk0b5xgdj6",
            _event(command="git commit -m 'Fix' -m 'Co-authored-by: Copilot'"),
        ),
        ("3pcxewp5hggr1vsn", _event(command="git reset --hard HEAD~2")),
        ("3pcxewp5hggr1vsn", _event(command="git clean -fdx")),
        ("3pcxewp5hggr1vsn", _event(command="git branch -D old-work")),
        ("3pcxewp5hggr1vsn", _event(command="git push origin :main")),
        (
            "xb24rc14cpcrsf4g",
            _event(file_path="dist/app.js", content="compiled output"),
        ),
        (
            "xb24rc14cpcrsf4g",
            _event(file_path="package-lock.json", patch="update dependency"),
        ),
        (
            "xb24rc14cpcrsf4g",
            _event(command="rm -f out/report.generated.json"),
        ),
        (
            "q88xgdmftag16dq9",
            _event(
                file_path=".github/workflows/issue.yml",
                patch="run: ./triage '${{ github.event.issue.title }}'",
            ),
        ),
        (
            "q88xgdmftag16dq9",
            _event(
                file_path=".github/workflows/manual.yml",
                patch="run: |\n  curl '${{ inputs.url }}'\n  echo done",
            ),
        ),
        (
            "qfh0h1cf4wt5aeg4",
            _event(
                file_path="docs/mysql.md",
                content="---\ntitle: MySQL Connector\n---",
            ),
        ),
        (
            "qfh0h1cf4wt5aeg4",
            _event(
                file_path="docs/redis.md",
                patch="- title: Redis Source\n+ title: Redis Integration",
            ),
        ),
        (
            "e3m4bdwj6gqcwpnn",
            _event(
                file_path="docs/start.mdx",
                patch="Read [setup](../setup.md#tokens).",
            ),
        ),
        (
            "sr09vpkt60y74r0q",
            _event(file_path="src/Parser.cs", content="namespace Demo;"),
        ),
        (
            "sr09vpkt60y74r0q",
            _event(
                file_path="tests/parser.cpp",
                patch="- // Licensed under the MIT license.\n+ #include <vector>",
            ),
        ),
    ],
)
def test_external_lexical_baseline_detects_observable_violations(rule_id, event):
    assert _lexical(rule_id, event) == "WARNING"


@pytest.mark.parametrize(
    ("rule_id", "event"),
    [
        ("98z9wvr031840p4g", _event(command="pnpm install")),
        (
            "98z9wvr031840p4g",
            _event(patch="Document why npm install is not used."),
        ),
        (
            "g3b7damk0b5xgdj6",
            _event(command="git commit -m 'Add Copilot integration tests'"),
        ),
        (
            "g3b7damk0b5xgdj6",
            _event(patch="Forbid Generated with Claude Code in commit messages."),
        ),
        ("3pcxewp5hggr1vsn", _event(command="git clean -ndx")),
        ("3pcxewp5hggr1vsn", _event(command="git restore --staged src/app.py")),
        ("3pcxewp5hggr1vsn", _event(command="git status --short")),
        (
            "xb24rc14cpcrsf4g",
            _event(file_path="src/app.ts", patch="add error handling"),
        ),
        (
            "xb24rc14cpcrsf4g",
            _event(command="sha256sum dist/app.js"),
        ),
        (
            "q88xgdmftag16dq9",
            _event(
                file_path=".github/workflows/issue.yml",
                patch=(
                    "env:\n  TITLE: ${{ github.event.issue.title }}\n"
                    "run: printf '%s' \"$TITLE\""
                ),
            ),
        ),
        (
            "q88xgdmftag16dq9",
            _event(
                file_path=".github/workflows/issue.yml",
                patch="with:\n  name: ${{ github.event.issue.title }}",
            ),
        ),
        (
            "q88xgdmftag16dq9",
            _event(
                file_path="docs/actions.md",
                patch="Never use run: echo ${{ inputs.name }}.",
            ),
        ),
        (
            "qfh0h1cf4wt5aeg4",
            _event(
                file_path="docs/mysql.md",
                content="---\ntitle: MySQL Source\n---",
            ),
        ),
        (
            "qfh0h1cf4wt5aeg4",
            _event(file_path="docs/mysql.md", patch="Clarify the example."),
        ),
        (
            "e3m4bdwj6gqcwpnn",
            _event(
                file_path="docs/index.mdx",
                patch="See [upstream](https://example.com/README.md).",
            ),
        ),
        (
            "e3m4bdwj6gqcwpnn",
            _event(file_path="docs/index.mdx", patch="See [setup](/setup/)."),
        ),
        (
            "e3m4bdwj6gqcwpnn",
            _event(file_path="docs/index.mdx", patch="![diagram](/img/flow.md)"),
        ),
        (
            "sr09vpkt60y74r0q",
            _event(
                file_path="src/Parser.cs",
                content="// SPDX-License-Identifier: MIT\nnamespace Demo;",
            ),
        ),
        (
            "sr09vpkt60y74r0q",
            _event(file_path="src/Parser.cs", patch="Add a bounds check."),
        ),
        (
            "sr09vpkt60y74r0q",
            _event(file_path="src/README.md", content="# Parser"),
        ),
    ],
)
def test_external_lexical_baseline_accepts_nonviolating_observations(rule_id, event):
    assert _lexical(rule_id, event) == "OK"


@pytest.mark.parametrize(
    "rule_id",
    [
        "98z9wvr031840p4g",
        "g3b7damk0b5xgdj6",
        "3pcxewp5hggr1vsn",
        "xb24rc14cpcrsf4g",
        "q88xgdmftag16dq9",
        "qfh0h1cf4wt5aeg4",
        "e3m4bdwj6gqcwpnn",
        "sr09vpkt60y74r0q",
    ],
)
def test_external_lexical_baseline_treats_malformed_input_as_no_signal(rule_id):
    assert _lexical(rule_id, "not serialized JSON") == "OK"
