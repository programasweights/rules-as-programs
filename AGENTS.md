# Rules as Programs — setup guide for coding agents

You are helping a user add **Rules as Programs** to their existing Cursor
project. Rules as Programs turns each agent rule into an independent Python
function (PAW-backed for fuzzy judgment) that audits the agent's reasoning and
actions and reports violations in a top-right menu-bar item. v1 is
**non-blocking** (observability only). Follow these steps.

## 1. Install the package

Run in the project root:

```bash
pip install rules-as-programs --extra-index-url https://pypi.programasweights.com/simple/
```

This also installs [ProgramAsWeights](https://programasweights.com) (`programasweights`),
which compiles each rule's natural-language spec into a small local neural
program. If `pip` is not the right environment manager here, use the project's
manager (e.g. `pipx install`, `uv pip install`, `poetry add`) with the same
`--extra-index-url`.

## 2. Initialize

```bash
rap init --scan
```

This installs the Cursor hook (`.cursor/hooks.json` + `.cursor/hooks/rap-hook.sh`),
scaffolds the built-in rule programs (`.py`) into `.cursor/rules-as-programs/rules/`,
drafts rule programs from any existing prose rules it finds (`--scan`), and
launches the daemon + menu-bar item.

- Prefer `rap init --scan` for a project-local setup (recommended).
- Use `rap init --global --scan` only if the user wants the rules to apply to
  **all** their projects (writes to `~/.cursor/`).

## 3. Convert the user's existing rules (do this well)

This is the highest-value step. For each existing plain-text rule you find in
`.cursor/rules/*.mdc`, `.cursor/rules/*.md`, `AGENTS.md`, or `.cursorrules`,
author a real rule program. `rap init --scan` will have created *disabled* `.py`
drafts in `.cursor/rules-as-programs/rules/` as a starting point; upgrade each.

A rule defaults to a managed fuzzy description in the UI. Its canonical source
is one `@rule`-decorated Python function under `rules/<id>/rule.py`; Advanced
Python can customize it. The 16-character `id` is immutable; Name is mutable.
Example:

```python
from rules_as_programs import rule

SPEC = """Decide whether the observed evidence violates this project rule.
Return ONLY one of: OK, INFO, WARNING, CRITICAL

Input: ## Latest message
<message and activity that follow the rule>
Output: OK

Input: ## Latest message
<message and activity that break the rule>
Output: WARNING"""

@rule(id="7km3v9c2xq4t8n1p",
      name="My project rule",
      on=["message", "session_stop"],
      inputs=["message", "thought", "shell_exec", "file_edit"],
      spec=SPEC)
def my_rule(ctx):
    "One-line title from the docstring."
    decision = ctx.paw(SPEC)(ctx.input())
    return ctx.finding(decision, "My project rule")
```

For each rule:

1. Decide what observable signal shows it being violated (a claim in a message, a
   missing shell command, an uncommitted change, a risky edit, etc.) and pick the
   right `on=[...]` event kinds.
2. Write a tight `SPEC` ending in `Return ONLY one of: ...` with 3-5 `Input:`/
   `Output:` examples that resemble what `ctx.evidence(...)` produces (see the
   built-in rules for the `## Probes` / `## Latest message` / `## Recent activity`
   format). `rap rules test` parses these cases directly; do not duplicate them
   in a separate `EXAMPLES` list.
3. Test and iterate until it passes: `rap rules test <id>`. Adjust the SPEC
   wording/examples, re-test. This is the PAW spec-engineering loop.
4. When it behaves well, enable it: `rap rules enable <id>`.
5. (Optional) Finalize for higher accuracy: `rap rules test <id> --compiler paw-ft-bs48`.

Keep each rule simple and single-purpose; several small rules beat one vague one.

## 4. Verify

```bash
rap doctor
rap rules list
```

`rap doctor` should show the PAW SDK installed, the daemon running, and the
project `hooks.json` present. `rap rules list` should list the built-in rules
plus any you converted.

## 5. Tell the user what to do next

- **Reload Cursor** (or restart it) so it picks up `.cursor/hooks.json`. Hooks
  do not activate until Cursor reloads them.
- Findings appear in the **top-right menu-bar item** as a severity-colored
  number beside the paw. A purple `?` separately indicates that an agent likely needs a
  reply; this is a local inference, not a violation or native approval signal.
- The project-aware Findings popover always exposes **+ Rule**. Clicking a
  finding opens the native Inspector with the exact rule snapshot, surrounding
  agent timeline, probes, and scrollable raw event log.
- Rule source opens in the fuzzy-first **Rule Editor**: Name, text description,
  Runs when, Reads, and optional severity-labelled cases. **Save
  Draft** does not change runtime behavior; **Check & Enable/Activate** switches
  the last-good active source only after success. Advanced Python remains
  available for arbitrary customization. Standard `Command-A` and `Control-A`
  select all text in the active field.
- **Rules for Project** is a shareable checklist stored in
  `.cursor/rules-as-programs/config.json`; personal hidden-finding choices stay
  local. Every rule row has a labelled **Actions…** menu, and the Rule Editor
  exposes **Delete Rule…**, **Remove Installed Rule…**, or **Use Shared
  Version…** as appropriate. Removal keeps finding and audit history.
- Rules live at `.cursor/rules-as-programs/rules/<id>/rule.py`; per-project
  violation logs are at `.cursor/rules-as-programs/log/audit.jsonl`.

## Notes

- Setup is non-destructive: `rap init` merges into an existing `hooks.json` and
  never overwrites existing rule files.
- Rules drafted by `--scan` are created **disabled**. Review the fuzzy
  description, optionally add realistic Input/Output cases, then use **Check &
  Enable** before relying on it.
- Judging is local-only and private (PAW runs on-device; the only remote step is
  the one-time compile). Do not commit secrets. The tool stores observed
  events/verdicts under `~/.cache/rules-as-programs/` (override with
  `RAP_STATE_DIR`); per-project audit logs are auto-`.gitignore`d.
