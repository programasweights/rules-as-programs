"""Built-in rule: notice unsynchronized local code changes."""

from rules_as_programs import rule

SPEC = """You audit whether a coding agent left meaningful local code changes that were
not synchronized to GitHub. You are given evidence: git status, recent commits,
count of unpushed commits, and the files the agent edited plus shell commands it
ran this turn.

Return ONLY one of: SYNCED, UNSYNCED, TRIVIAL

- SYNCED: working tree clean AND no unpushed commits (changes are on GitHub).
- UNSYNCED: real source changes exist that are uncommitted OR committed but not pushed.
- TRIVIAL: the only changes are inconsequential (e.g. a scratch file, logs).

Input: ## Probes
[git_status]
 M src/api.py
[recent_commits]
a1b2c3d earlier work
[unpushed_commits]
0
## Recent activity
- (file_edit) edit src/api.py
Output: UNSYNCED

Input: ## Probes
[git_status]
[recent_commits]
9f8e7d6 add feature
[unpushed_commits]
0
## Recent activity
- (shell_exec) $ git push
Output: SYNCED

Input: ## Probes
[git_status]
[recent_commits]
1122334 add feature
[unpushed_commits]
2
## Recent activity
- (shell_exec) $ git commit -am "add feature"
Output: UNSYNCED

Input: ## Probes
[git_status]
 M notes.scratch.txt
[recent_commits]
0aa11bb docs
[unpushed_commits]
0
## Recent activity
- (file_edit) edit notes.scratch.txt
Output: TRIVIAL"""

EXAMPLES = [
    ("## Probes\n[git_status]\n M src/auth.py\n M src/server.py\n[recent_commits]\n"
     "deadbee older\n[unpushed_commits]\n0\n## Recent activity\n"
     "- (file_edit) edit src/auth.py\n- (file_edit) edit src/server.py", "UNSYNCED"),
    ("## Probes\n[git_status]\n[recent_commits]\nabc1234 ship it\n[unpushed_commits]\n0\n"
     "## Recent activity\n- (shell_exec) $ git push origin main", "SYNCED"),
    ("## Probes\n[git_status]\n M cache.tmp\n[recent_commits]\nabc1234 x\n[unpushed_commits]\n0\n"
     "## Recent activity\n- (file_edit) edit cache.tmp", "TRIVIAL"),
]


@rule(severity="warn", on=["session_stop"], spec=SPEC, examples=EXAMPLES)
def github_sync(ctx):
    "Use GitHub to synchronize code."
    evidence = ctx.evidence(
        probes={
            "git_status": "git status --porcelain=v1 2>/dev/null | head -50",
            "recent_commits": "git log --oneline -3 2>/dev/null",
            "unpushed_commits": "git rev-list --count @{u}..HEAD 2>/dev/null || echo unknown",
        },
        include=["file_edit", "shell_exec"],
    )
    if ctx.paw(SPEC)(evidence) == "UNSYNCED":
        return "Meaningful local changes are not committed/pushed to GitHub."
