from rules_as_programs import rule


SPEC = """The input is the exact serialized JSON value of a Codex PreToolUse
/tool_input field. Decide whether a proposed GitHub Actions edit places an
untrusted GitHub expression directly inside a shell run block. Values from
inputs, step outputs, pull-request or issue bodies and titles, head refs, and
branch names are untrusted. Passing the expression through an env mapping and
using a quoted shell variable is allowed. Expressions used outside run blocks
and prose that only discusses the pattern are allowed.
Return ONLY one of: OK, WARNING

Input: {"file_path":".github/workflows/ci.yml","patch":"run: echo '${{ github.event.issue.title }}'"}
Output: WARNING

Input: {"file_path":".github/workflows/ci.yml","patch":"run: deploy ${{ inputs.environment }}"}
Output: WARNING

Input: {"file_path":".github/workflows/ci.yml","patch":"env:\n  TITLE: ${{ github.event.issue.title }}\nrun: printf '%s\\n' \"$TITLE\""}
Output: OK

Input: {"file_path":"docs/security.md","patch":"Never interpolate ${{ inputs.name }} in run blocks."}
Output: OK"""


@rule(
    id="q88xgdmftag16dq9",
    name="Keep untrusted expressions out of Actions run blocks",
    trigger="PreToolUse",
    spec=SPEC,
)
def no_untrusted_actions_interpolation(ctx):
    """Keep untrusted GitHub expressions out of shell run blocks."""
    return ctx.result(ctx.paw(SPEC)(ctx.input))
