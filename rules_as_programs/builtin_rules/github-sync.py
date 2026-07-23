from rules_as_programs import rule

# RAP_MANAGED_FUZZY_V1
SPEC = """Decide whether meaningful project source changes remain unsynchronized with GitHub. A clean tree with no unpushed commits is allowed. Inconsequential scratch/log changes are allowed. Real source changes that are uncommitted or committed but not pushed are a violation.
Return ONLY one of: OK, VIOLATION

Input: ## Probes
[git_status]
 M src/auth.py
[unpushed_commits]
0
## Recent activity
- (file_edit) edit src/auth.py
Output: VIOLATION

Input: ## Probes
[git_status]
[unpushed_commits]
0
## Recent activity
- (shell_exec) $ git push origin main
Output: OK

Input: ## Probes
[git_status]
[unpushed_commits]
2
## Recent activity
- (shell_exec) $ git commit -am "add feature"
Output: VIOLATION

Input: ## Probes
[git_status]
 M notes.scratch.txt
[unpushed_commits]
0
## Recent activity
- (file_edit) edit notes.scratch.txt
Output: OK"""


@rule(
    id="6d379c19-a80a-5283-a596-24ceee35089b",
    name="Use GitHub to synchronize code",
    on=["session_stop"],
    inputs=["file_edit", "shell_exec"],
    probes={
        "git_status": "git status --porcelain=v1 2>/dev/null | head -50",
        "recent_commits": "git log --oneline -3 2>/dev/null",
        "unpushed_commits": "git rev-list --count @{u}..HEAD 2>/dev/null || echo unknown",
    },
    severity="warn",
    spec=SPEC,
)
def use_github_to_synchronize_code(ctx):
    """Use GitHub to synchronize code"""
    if ctx.paw(SPEC)(ctx.input()) == "VIOLATION":
        return "Meaningful local changes are not committed or pushed to GitHub."
