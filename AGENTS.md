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

Input: <exact Cursor trigger field that follows the rule>
Output: OK

Input: <exact Cursor trigger field that breaks the rule>
Output: WARNING"""

@rule(id="7km3v9c2xq4t8n1p",
      name="My project rule",
      trigger="afterAgentResponse",
      spec=SPEC)
def my_rule(ctx):
    "One-line title from the docstring."
    decision = ctx.paw(SPEC)(ctx.input)
    return ctx.result(decision)
```

For each rule:

1. Choose one Cursor trigger whose predefined field directly contains the
   observable signal. Basic rules never aggregate events.
2. Write a tight `SPEC` ending in `Return ONLY one of: ...` with 3-5 `Input:`/
   `Output:` examples containing that exact scalar field. `rap rules test`
   parses these cases directly; do not duplicate them
   in a separate `EXAMPLES` list.
3. Test and iterate until it passes: `rap rules test <id>`. Adjust the SPEC
   wording/examples, re-test. This is the PAW spec-engineering loop.
4. When it behaves well, enable it: `rap rules enable <id>`.
5. (Optional) Use `paw.list_compilers()` to discover a current
   higher-accuracy compiler, then pass its name with `--compiler`.

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
  number beside the paw. The count remains primary when monitoring has an
  operational issue; concrete project/rule failures appear separately with
  Retry/Test/Details actions. A purple `?` separately indicates that an agent
  likely needs a reply.
- The project-aware Findings popover always exposes **+ Rule**. Clicking a
  finding opens the latest occurrence as an expanded tray row with the exact
  evaluated input. Session Activity is separate and never silently evaluated. **Edit Rule…** retains
  that strict finding record as tuning/test-case context.
- **All Projects → + Rule** creates an all-project draft directly; when one
  project is selected, the same action creates a confirmed project-scoped
  draft. Project-header **… → Add Rule…** always targets that project.
- The Findings list keeps older-revision findings beneath their project and
  matching current rule, with a preview, occurrence count, and consistent
  review control. Project and advanced finding actions live in `…` menus.
- Grouping never implies bulk review: one-occurrence rows have a direct check,
  while multi-occurrence rows disclose individually reviewable events.
  **Review All N Occurrences…** must remain explicit and confirmed.
- The finding Inspector wraps prose by default and leaves structured
  commands/code/JSON unwrapped. **… → Line Wrapping** persists an Auto,
  Always, or Never override without changing copied raw input.
- Rule source opens in the intent-first **Rule Editor**: Name, one Trigger, its
  derived Input, and the exact PAW `SPEC`. RAP never appends or rewrites the
  specification; it warns if `OK` plus a finding level are missing. **Deploy**
  validates, tests, compiles,
  activates, and applies All Projects or Selected Projects coverage; failure
  leaves the previous deployment running. **View Python…** exposes the
  underlying program. Standard `Command-A` and `Control-A` select all text in
  the active field; `Command-S` saves a local draft.
- **Compilation…** distinguishes the deployed compiler from the editor draft's
  compiler and groups compatible options by runtime family. Builds always use
  the exact current draft. **Deploy** is the only activation action and commits
  the draft, compiler snapshot, and program together.
- **Deploy When Ready** persists the exact draft/compiler/test/scope intent
  while a long compiler builds. Tests never run implicitly: missing results
  require an explicit Run Tests or Deploy Without Testing choice. Any
  subsequent draft edit cancels the queue; accepted queues dismiss the editor.
- All deployments use persistent idempotency IDs. A disconnected editor checks
  status after reconnecting and retries only an unchanged draft. Daemon
  stdout/stderr and worker tracebacks are retained in
  `~/.cache/rules-as-programs/daemon-stderr.log`.
- **Rules for Project** is a shareable checklist stored in
  `.cursor/rules-as-programs/config.json`; personal hidden-finding choices stay
  local. Every rule row has a labelled **Actions…** menu, and the Rule Editor
  exposes **Delete Rule…**, **Remove Installed Rule…**, or **Use Shared
  Version…** as appropriate. Removal moves orphaned open findings to
  **Reviewed** as **Rule deleted**, while keeping their recorded source and
  audit history.
- Rules live at `.cursor/rules-as-programs/rules/<id>/rule.py`; per-project
  violation logs are at `.cursor/rules-as-programs/log/audit.jsonl`; all
  invocation outcomes are at `evaluations.jsonl` and in Evaluation History.
- Rule names are mutable display metadata. Rename operations must not stale
  findings, invalidate compiler candidates, or require new PAW programs;
  behavior identity comes from the canonical metadata-neutral behavior hash.
- Optional validation inputs live beside the rule in `tests.json`; they are
  never added to the PAW `SPEC`. Per-case results persist locally in
  `~/.cache/rules-as-programs/validation-results.db`, keyed by exact spec,
  compiler snapshot, and case content.
- Local PAW/llama.cpp function creation, warmup, and inference are strictly
  serialized through one supervised process-global subprocess. A native timeout
  kills and replaces that worker. Compilation uses a separate executor; never
  increase local inference concurrency.

## Notes

- Setup is non-destructive: `rap init` merges into an existing `hooks.json` and
  never overwrites existing rule files.
- Rules drafted by `--scan` are created **disabled**. Review the fuzzy
  description and project coverage, then use **Deploy** before relying on it.
- Judging is local-only and private (PAW runs on-device; the only remote step is
  the one-time compile). Do not commit secrets. The tool stores observed
  events/verdicts under `~/.cache/rules-as-programs/` (override with
  `RAP_STATE_DIR`); per-project audit logs are auto-`.gitignore`d.
