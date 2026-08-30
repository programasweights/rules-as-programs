from rules_as_programs import rule

SPEC = """The input is the exact serialized JSON value of a Codex PreToolUse /tool_input field. Decide whether it directly transfers source code, a code repository, or a project directory to a remote machine using rsync, scp, sftp, or a similar file-transfer command. Transfers of datasets, checkpoints, logs, and experiment outputs are allowed. Git push is allowed. Text that merely mentions a transfer command without executing it is allowed.
Return ONLY one of: OK, WARNING

Input: {"command":"rsync -av ./src/ user@server:~/project/src/"}
Output: WARNING

Input: {"command":"scp train.py user@server:~/project/"}
Output: WARNING

Input: {"command":"rsync -av ./dataset/ user@server:~/data/"}
Output: OK

Input: {"command":"git push origin main"}
Output: OK

Input: {"patch":"Document this example: rsync -av src/ host:/srv/src/"}
Output: OK"""


@rule(
    id="78v34vpkzm2jp4rx",
    name="Use Git for code synchronization",
    trigger="PreToolUse",
    spec=SPEC,
)
def use_git_for_code_synchronization(ctx):
    """Use Git for code synchronization"""
    return ctx.result(ctx.paw(SPEC)(ctx.input))
