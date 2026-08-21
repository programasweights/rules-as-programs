# Rules as Programs — setup guide for coding agents

You are helping a user add **Rules as Programs** to their existing Cursor
project. Rules as Programs turns each agent rule into an independent Python
function (PAW-backed for fuzzy judgment) that audits the agent's reasoning and
actions and reports violations. v1 is **non-blocking** (observability only).
macOS has the full native menu-bar inbox and Rule Editor; Linux and Windows use
a reduced tray menu. Follow these steps.

## 1. Install the package

Run in the project root:

```bash
python -m pip install "git+https://github.com/programasweights/rules-as-programs.git" \
  --extra-index-url https://pypi.programasweights.com/simple/
```

This installs Rules as Programs directly from GitHub. It also installs
[ProgramAsWeights](https://programasweights.com) (`programasweights`), which
compiles each rule's natural-language spec into a small local neural program.
The ProgramAsWeights package index supplies prebuilt `llama-cpp-python` wheels
for local inference; it does not host Rules as Programs. For an isolated CLI
installation, the equivalent pipx form is:

```bash
pipx install "git+https://github.com/programasweights/rules-as-programs.git" \
  --pip-args="--extra-index-url https://pypi.programasweights.com/simple/"
```

Python 3.10 or newer is required. Use an environment that will remain available
because the hook and login-autostart entry retain its interpreter path.

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

This is the highest-value step. For each independent rule expressed in
`.cursor/rules/*.mdc`, `.cursor/rules/*.md`, `AGENTS.md`, or `.cursorrules`,
author a real rule program. `rap init --scan` creates one *disabled* rough draft
per top-level source document from a short excerpt; it does not split documents
into rules. Treat those drafts as starting points, create separate programs
where needed, and do not rerun the scanner because it can create duplicates.

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
   in a separate `EXAMPLES` list. Never put secrets in the `SPEC` or examples:
   PAW sends the specification to its compile service.
3. Test and iterate until it passes: `rap rules test <id>`. Adjust the SPEC
   wording/examples, re-test. This is the PAW spec-engineering loop.
4. For agent-led CLI setup, `rap rules enable <id>` assigns the working source
   so it can run in this project. It does not create a deployed revision or
   persist a compiler choice. Append `--global` only when the user explicitly
   requested a global setup.
5. On macOS, tell the user to open the rule in Rule Editor and click **Deploy**
   for the managed compiler, revision, migration, and coverage lifecycle. On
   Linux/Windows, stop after test + enable and explain that the reduced tray has
   no managed Deploy action.
6. (Optional) Use `paw.list_compilers()` to discover compilers and pass one to
   `rap rules test --compiler`; that selection applies only to that test run.

Keep each rule simple and single-purpose; several small rules beat one vague one.

## 4. Verify

```bash
rap doctor
rap rules list
```

`rap doctor` should show the PAW SDK installed, the daemon running, and the
project `hooks.json` present. `rap rules list` should list the built-in rules
plus any you converted. These checks do not prove that Cursor reloaded the
hook. After reloading Cursor, run one agent turn and inspect the macOS tray's
project activity or `.cursor/rules-as-programs/log/evaluations.jsonl`.

## 5. Tell the user what to do next

- **Reload Cursor** (or restart it) so it picks up `.cursor/hooks.json`. Hooks
  do not activate until Cursor reloads them.
- The detailed interface below is macOS-only. Linux and Windows expose a
  reduced system-tray menu; Windows users must start it with `rap tray`.
- Findings appear in the **top-right menu-bar item** as a severity-colored
  number beside the paw. The count remains primary when monitoring has an
  operational issue; concrete project/rule failures appear separately with
  Retry/Test/Details actions. A purple `?` separately indicates that an agent
  likely needs a reply.
- The project-aware Findings popover always exposes **+ Rule**. Clicking a
  finding closes the popover and opens a separate Inspector with the exact
  evaluated input. Session Activity is separate and never silently evaluated.
  **Edit Rule…** retains that strict finding record as tuning/test-case context.
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
  validates the source, compiles, activates, and applies All Projects or
  Selected Projects coverage; failure leaves the previous deployment running.
  Validation Cases run only when the user clicks **Run Tests** and never gate
  Deploy or compiler promotion. **View Python…** exposes the underlying
  program. Standard `Command-A` and `Control-A` select all text in the active
  field; `Command-S` saves a local draft.
- **Compilation…** defaults to **Automatic (Recommended)**: Deploy activates a
  compatible fast artifact, then, when a compatible finetune compiler is
  available, a durable background job builds, warms, and promotes it if that
  behavior is still current. **Explicit compiler** pins a catalog compiler.
  Builds always use the exact current draft.
- **Deploy When Ready** persists the exact draft/compiler/scope intent while a
  compiler builds. Any subsequent draft edit cancels the queue; accepted
  queues dismiss the editor.
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
- Project-owned sources live at
  `.cursor/rules-as-programs/rules/<id>/rule.py`; shared/deployed sources live
  at `~/.cursor/rules-as-programs/rules/<id>/rule.py`. A project override that
  shares a library rule's ID cannot currently Deploy until the source conflict
  is resolved. Project assignment lives in
  `.cursor/rules-as-programs/config.json`; per-project finding occurrences are
  at `.cursor/rules-as-programs/log/audit.jsonl`, and all invocation outcomes
  are at `evaluations.jsonl` and in Evaluation History.
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

- `rap init` merges valid existing hook JSON and preserves existing rule files.
  Back up malformed hook configuration because it may be replaced.
- Rules drafted by `--scan` are created **disabled**. Review the fuzzy
  description and project coverage. On macOS, use **Deploy** before relying on
  the rule. On Linux/Windows, test and enable it from the CLI; explain that this
  bypasses managed revision and compiler deployment.
- Managed PAW rules judge observed inputs locally. Creating or refreshing an
  artifact sends the rule `SPEC`, not observed trigger inputs, to the compile
  service; this can happen again after spec/compiler changes or Automatic
  optimization. Advanced Python rules are unsandboxed and can access or
  transmit their inputs. RAP stores observed events and verdicts locally in
  plaintext under `~/.cache/rules-as-programs/` (override with `RAP_STATE_DIR`)
  and project log directories. Pause stops evaluation, not collection. Do not
  commit secrets, and verify project ignore rules before sharing generated
  logs or test cases.
