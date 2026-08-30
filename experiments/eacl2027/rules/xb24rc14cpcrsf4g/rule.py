from rules_as_programs import rule


SPEC = """The input is the exact serialized JSON value of a Codex PreToolUse
/tool_input field. Decide whether it directly writes, edits, or deletes a build
output, generated file, or dependency lockfile. Reading or searching
such a file is allowed. Editing ordinary source, tests, or documentation is
allowed. A patch that only documents the policy is allowed.
Return ONLY one of: OK, WARNING

Input: {"file_path":"dist/app.js","content":"compiled output"}
Output: WARNING

Input: {"command":"rm -f pnpm-lock.yaml"}
Output: WARNING

Input: {"command":"sed -n '1,80p' package-lock.json"}
Output: OK

Input: {"file_path":"src/app.ts","patch":"add error handling"}
Output: OK"""


@rule(
    id="xb24rc14cpcrsf4g",
    name="Do not modify generated outputs or lockfiles",
    trigger="PreToolUse",
    spec=SPEC,
)
def avoid_generated_outputs(ctx):
    """Do not modify generated outputs or dependency lockfiles."""
    return ctx.result(ctx.paw(SPEC)(ctx.input))
