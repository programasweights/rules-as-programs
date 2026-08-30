from rules_as_programs import rule


SPEC = """The input is the exact serialized JSON value of a Codex PreToolUse
/tool_input field. Decide whether it executes npm or yarn for a JavaScript
package-management task instead of pnpm. Commands that use pnpm are allowed.
Running node directly, editing prose that mentions npm or yarn, and inspecting
package metadata without executing a disallowed package manager are allowed.
Return ONLY one of: OK, WARNING

Input: {"command":"npm install zod"}
Output: WARNING

Input: {"command":"yarn test"}
Output: WARNING

Input: {"command":"pnpm install"}
Output: OK

Input: {"patch":"Document why npm install is not used here."}
Output: OK"""


@rule(
    id="98z9wvr031840p4g",
    name="Use pnpm rather than npm or yarn",
    trigger="PreToolUse",
    spec=SPEC,
)
def use_pnpm(ctx):
    """Use pnpm rather than npm or yarn for package-management tasks."""
    return ctx.result(ctx.paw(SPEC)(ctx.input))
